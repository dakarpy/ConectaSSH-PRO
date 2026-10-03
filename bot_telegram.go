package main

// bot_telegram.go — minimal Telegram Bot API client built on net/http.
// No third-party dependency.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const tgAPIBase = "https://api.telegram.org/bot"

// ---------- Wire types (subset) ----------

type tgUpdate struct {
	UpdateID      int64            `json:"update_id"`
	Message       *tgMessage       `json:"message"`
	CallbackQuery *tgCallbackQuery `json:"callback_query"`
}

type tgMessage struct {
	MessageID int64   `json:"message_id"`
	From      *tgUser `json:"from"`
	Chat      tgChat  `json:"chat"`
	Text      string  `json:"text"`
}

type tgCallbackQuery struct {
	ID      string     `json:"id"`
	From    tgUser     `json:"from"`
	Message *tgMessage `json:"message"`
	Data    string     `json:"data"`
}

type tgUser struct {
	ID        int64  `json:"id"`
	FirstName string `json:"first_name"`
	Username  string `json:"username"`
}

type tgChat struct {
	ID int64 `json:"id"`
}

type tgInlineKeyboard struct {
	InlineKeyboard [][]tgInlineButton `json:"inline_keyboard"`
}

type tgInlineButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data,omitempty"`
	URL          string `json:"url,omitempty"`
}

// ---------- Client ----------

type tgClient struct {
	token string
	hc    *http.Client
}

func newTGClient(token string) *tgClient {
	return &tgClient{token: token, hc: &http.Client{Timeout: 65 * time.Second}}
}

type tgResponse struct {
	OK          bool            `json:"ok"`
	Description string          `json:"description"`
	Result      json.RawMessage `json:"result"`
}

func (c *tgClient) call(ctx context.Context, method string, payload interface{}) (json.RawMessage, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tgAPIBase+c.token+"/"+method, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var tr tgResponse
	if err := json.Unmarshal(data, &tr); err != nil {
		return nil, fmt.Errorf("telegram %s: bad response: %s", method, string(data))
	}
	if !tr.OK {
		return nil, fmt.Errorf("telegram %s: %s", method, tr.Description)
	}
	return tr.Result, nil
}

// getUpdates long-polls. offset is the next update_id to fetch.
func (c *tgClient) getUpdates(ctx context.Context, offset int64, timeoutSec int) ([]tgUpdate, error) {
	payload := map[string]interface{}{
		"offset":          offset,
		"timeout":         timeoutSec,
		"allowed_updates": []string{"message", "callback_query"},
	}
	raw, err := c.call(ctx, "getUpdates", payload)
	if err != nil {
		return nil, err
	}
	var ups []tgUpdate
	if err := json.Unmarshal(raw, &ups); err != nil {
		return nil, err
	}
	return ups, nil
}

func (c *tgClient) sendMessage(ctx context.Context, chatID int64, text string, kb *tgInlineKeyboard) (int64, error) {
	payload := map[string]interface{}{
		"chat_id":                  chatID,
		"text":                     text,
		"parse_mode":               "HTML",
		"disable_web_page_preview": true,
	}
	if kb != nil {
		payload["reply_markup"] = kb
	}
	raw, err := c.call(ctx, "sendMessage", payload)
	if err != nil {
		return 0, err
	}
	var m tgMessage
	_ = json.Unmarshal(raw, &m)
	return m.MessageID, nil
}

func (c *tgClient) editMessageText(ctx context.Context, chatID, messageID int64, text string, kb *tgInlineKeyboard) error {
	payload := map[string]interface{}{
		"chat_id":                  chatID,
		"message_id":               messageID,
		"text":                     text,
		"parse_mode":               "HTML",
		"disable_web_page_preview": true,
	}
	if kb != nil {
		payload["reply_markup"] = kb
	}
	_, err := c.call(ctx, "editMessageText", payload)
	return err
}

func (c *tgClient) answerCallback(ctx context.Context, callbackID, text string) error {
	payload := map[string]interface{}{"callback_query_id": callbackID}
	if text != "" {
		payload["text"] = text
	}
	_, err := c.call(ctx, "answerCallbackQuery", payload)
	return err
}

// sendPhotoBytes uploads a photo (e.g. a PIX QR PNG) via multipart.
func (c *tgClient) sendPhotoBytes(ctx context.Context, chatID int64, photo []byte, filename, caption string, kb *tgInlineKeyboard) (int64, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("chat_id", strconv.FormatInt(chatID, 10))
	if caption != "" {
		_ = w.WriteField("caption", caption)
		_ = w.WriteField("parse_mode", "HTML")
	}
	if kb != nil {
		kbJSON, _ := json.Marshal(kb)
		_ = w.WriteField("reply_markup", string(kbJSON))
	}
	fw, err := w.CreateFormFile("photo", filename)
	if err != nil {
		return 0, err
	}
	if _, err := fw.Write(photo); err != nil {
		return 0, err
	}
	_ = w.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tgAPIBase+c.token+"/sendPhoto", &buf)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var tr tgResponse
	if err := json.Unmarshal(data, &tr); err != nil || !tr.OK {
		return 0, fmt.Errorf("telegram sendPhoto: %s", string(data))
	}
	var m tgMessage
	_ = json.Unmarshal(tr.Result, &m)
	return m.MessageID, nil
}

func (c *tgClient) deleteWebhook(ctx context.Context) error {
	_, err := c.call(ctx, "deleteWebhook", map[string]interface{}{"drop_pending_updates": false})
	return err
}

// getMe validates the token and returns the bot username.
func (c *tgClient) getMe(ctx context.Context) (string, error) {
	raw, err := c.call(ctx, "getMe", map[string]interface{}{})
	if err != nil {
		return "", err
	}
	var me tgUser
	_ = json.Unmarshal(raw, &me)
	return me.Username, nil
}

// ---------- helpers ----------

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
