package main

// bot_mercadopago.go — Mercado Pago PIX client + inbound webhook handler.
// Built on net/http; no third-party dependency.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const mpAPIBase = "https://api.mercadopago.com"

type mpClient struct {
	accessToken string
	hc          *http.Client
}

func newMPClient(accessToken string) *mpClient {
	return &mpClient{accessToken: accessToken, hc: &http.Client{Timeout: 25 * time.Second}}
}

// mpPixResult holds what the bot needs to show the buyer.
type mpPixResult struct {
	PaymentID string
	QRCode    string // copy-and-paste PIX string
	QRBase64  string // PNG image, base64 (no data: prefix)
	Status    string
}

// CreatePixPayment creates a PIX charge and returns the QR data.
// amountCents is BRL cents; expiresAt bounds the QR validity.
func (c *mpClient) CreatePixPayment(ctx context.Context, amountCents int, description, payerEmail, externalRef string, expiresAt time.Time, idempotencyKey string) (*mpPixResult, error) {
	if payerEmail == "" {
		payerEmail = "comprador@example.com"
	}
	body := map[string]interface{}{
		"transaction_amount": float64(amountCents) / 100.0,
		"description":        description,
		"payment_method_id":  "pix",
		"payer":              map[string]interface{}{"email": payerEmail},
		"date_of_expiration": expiresAt.Format("2006-01-02T15:04:05.000-07:00"),
		"external_reference": externalRef,
	}
	raw, err := c.do(ctx, http.MethodPost, "/v1/payments", body, idempotencyKey)
	if err != nil {
		return nil, err
	}
	var resp struct {
		ID                 json.Number `json:"id"`
		Status             string      `json:"status"`
		PointOfInteraction struct {
			TransactionData struct {
				QRCode       string `json:"qr_code"`
				QRCodeBase64 string `json:"qr_code_base64"`
			} `json:"transaction_data"`
		} `json:"point_of_interaction"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("mp create payment: parse: %w", err)
	}
	if resp.ID.String() == "" {
		return nil, fmt.Errorf("mp create payment: no id in response: %s", string(raw))
	}
	return &mpPixResult{
		PaymentID: resp.ID.String(),
		QRCode:    resp.PointOfInteraction.TransactionData.QRCode,
		QRBase64:  resp.PointOfInteraction.TransactionData.QRCodeBase64,
		Status:    resp.Status,
	}, nil
}

// GetPaymentStatus returns the current status of a payment (e.g. "approved").
func (c *mpClient) GetPaymentStatus(ctx context.Context, paymentID string) (string, error) {
	raw, err := c.do(ctx, http.MethodGet, "/v1/payments/"+paymentID, nil, "")
	if err != nil {
		return "", err
	}
	var resp struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return "", err
	}
	return resp.Status, nil
}

func (c *mpClient) do(ctx context.Context, method, path string, body interface{}, idempotencyKey string) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, mpAPIBase+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Content-Type", "application/json")
	if idempotencyKey != "" {
		req.Header.Set("X-Idempotency-Key", idempotencyKey)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("mercado pago %s %s: http %d: %s", method, path, resp.StatusCode, string(data))
	}
	return data, nil
}

// verifyMPSignature validates the x-signature header per Mercado Pago's spec.
// Manifest: "id:<dataID>;request-id:<x-request-id>;ts:<ts>;" HMAC-SHA256(secret).
func verifyMPSignature(xSignature, xRequestID, dataID, secret string) bool {
	if secret == "" {
		return false
	}
	var ts, v1 string
	for _, part := range strings.Split(xSignature, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch strings.TrimSpace(kv[0]) {
		case "ts":
			ts = strings.TrimSpace(kv[1])
		case "v1":
			v1 = strings.TrimSpace(kv[1])
		}
	}
	if ts == "" || v1 == "" {
		return false
	}
	if timestamp, err := strconv.ParseInt(ts, 10, 64); err != nil || timestamp <= 0 {
		return false
	}
	parts := make([]string, 0, 3)
	if dataID != "" {
		parts = append(parts, "id:"+strings.ToLower(dataID))
	}
	if xRequestID != "" {
		parts = append(parts, "request-id:"+xRequestID)
	}
	parts = append(parts, "ts:"+ts)
	manifest := strings.Join(parts, ";") + ";"
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(manifest))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(v1))
}

// handleMPWebhook is the public endpoint Mercado Pago calls on payment events.
// It never trusts the body: it re-fetches the payment and fulfills idempotently.
func handleMPWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	b := currentBot()
	if b == nil {
		w.WriteHeader(http.StatusOK) // bot disabled; acknowledge to stop retries
		return
	}
	// Only honor webhooks when confirmation mode is "webhook". In polling mode
	// the poller drives fulfillment; ignore unsolicited posts to this endpoint.
	if b.cfg.MPConfirmMode != "webhook" {
		w.WriteHeader(http.StatusOK)
		return
	}
	// Extract the payment id from body or query.
	dataID := r.URL.Query().Get("data.id")
	if dataID == "" {
		dataID = r.URL.Query().Get("id")
	}
	signatureDataID := dataID
	var payload struct {
		Type   string `json:"type"`
		Action string `json:"action"`
		Data   struct {
			ID json.Number `json:"id"`
		} `json:"data"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "invalid webhook body", http.StatusRequestEntityTooLarge)
		return
	}
	if len(body) > 0 {
		_ = json.Unmarshal(body, &payload)
		if dataID == "" {
			dataID = payload.Data.ID.String()
		}
	}
	if dataID == "" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if len(dataID) > 32 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	for _, char := range dataID {
		if char < '0' || char > '9' {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}

	if !verifyMPSignature(r.Header.Get("x-signature"), r.Header.Get("x-request-id"), signatureDataID, b.cfg.MPWebhookSecret) {
		log.Printf("[bot] MP webhook: invalid signature for payment %s", dataID)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Acknowledge immediately; process in the background so MP doesn't time out.
	go b.processPaymentByMPID(dataID)
	w.WriteHeader(http.StatusOK)
}

// centsToBRL formats cents as "R$ 12,34".
func centsToBRL(cents int) string {
	reais := cents / 100
	cent := cents % 100
	return "R$ " + strconv.Itoa(reais) + "," + fmt.Sprintf("%02d", cent)
}
