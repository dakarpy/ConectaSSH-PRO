package main

// bot_payments.go — payment polling, webhook processing, and idempotent delivery.

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"
)

// ---------- Polling mode ----------

func (b *Bot) runPaymentPoller() {
	d, err := time.ParseDuration(b.cfg.MPPollInterval)
	if err != nil || d < 5*time.Second {
		d = 20 * time.Second
	}
	t := time.NewTicker(d)
	defer t.Stop()
	log.Printf("[bot] payment poller started (interval=%s)", d)
	for {
		select {
		case <-b.ctx.Done():
			log.Printf("[bot] payment poller stopped")
			return
		case <-t.C:
			b.pollPending()
		}
	}
}

func (b *Bot) pollPending() {
	txns, err := b.store.ListPendingTransactions(b.ctx)
	if err != nil {
		log.Printf("[bot] poll list: %v", err)
		return
	}
	now := time.Now()
	for _, txn := range txns {
		if txn.ExpiresAt != nil && now.After(*txn.ExpiresAt) {
			_ = b.store.SetTransactionStatus(b.ctx, txn.ID, "expired")
			b.notify(txn.TelegramID, fmt.Sprintf("⌛ O PIX do pedido #%d expirou. Gere um novo pagamento se ainda quiser.", txn.ID))
			continue
		}
		if b.mp == nil {
			continue
		}
		status, err := b.mp.GetPaymentStatus(b.ctx, txn.MPPaymentID)
		if err != nil {
			continue
		}
		if status == "approved" {
			b.tryFulfill(txn.ID)
		}
	}
}

// ---------- Webhook mode ----------

// processPaymentByMPID is invoked from the Mercado Pago webhook handler.
func (b *Bot) processPaymentByMPID(mpID string) {
	txn, err := b.store.GetTransactionByMPID(b.ctx, mpID)
	if err != nil {
		log.Printf("[bot] webhook: no txn for mp payment %s: %v", mpID, err)
		return
	}
	if b.mp == nil {
		return
	}
	status, err := b.mp.GetPaymentStatus(b.ctx, mpID)
	if err != nil {
		log.Printf("[bot] webhook: get status %s: %v", mpID, err)
		return
	}
	if status == "approved" {
		b.tryFulfill(txn.ID)
	}
}

// ---------- Idempotent fulfillment ----------

// tryFulfill flips the txn to approved exactly once, then delivers.
func (b *Bot) tryFulfill(txnID int) {
	ok, err := b.store.MarkTransactionApproved(b.ctx, txnID)
	if err != nil {
		log.Printf("[bot] mark approved %d: %v", txnID, err)
		return
	}
	if !ok {
		return // already fulfilled by another path
	}
	txn, err := b.store.GetTransaction(b.ctx, txnID)
	if err != nil {
		log.Printf("[bot] fulfill get txn %d: %v", txnID, err)
		return
	}
	b.fulfillTransaction(txn)
}

func (b *Bot) fulfillTransaction(txn *BotTransaction) {
	switch txn.Type {
	case "credit_topup":
		bal, err := b.store.AdjustCredits(b.ctx, txn.TelegramID, txn.Credits, "topup", &txn.ID)
		if err != nil {
			log.Printf("[bot] topup credit %d: %v", txn.ID, err)
			b.notify(txn.TelegramID, "❌ Pagamento aprovado, mas houve um erro ao creditar. Contate o suporte.")
			return
		}
		b.notify(txn.TelegramID, fmt.Sprintf("✅ Recarga aprovada! +%d créditos.\n💳 Saldo atual: %d créditos.", txn.Credits, bal))
	case "plan_renewal":
		b.fulfillRenewal(txn)
	default:
		b.fulfillPurchase(txn)
	}
}

func (b *Bot) fulfillPurchase(txn *BotTransaction) {
	if txn.PlanID == nil {
		return
	}
	p, err := b.store.GetPlan(b.ctx, *txn.PlanID)
	if err != nil {
		log.Printf("[bot] fulfill purchase: plan %v: %v", txn.PlanID, err)
		b.notify(txn.TelegramID, "❌ Pagamento aprovado, mas o plano não foi encontrado. Contate o suporte.")
		return
	}
	exp := time.Now().Add(time.Duration(p.Days) * 24 * time.Hour)
	if p.Kind == "xray" {
		uuid, link, err := createXrayClient(b.ctx, b.store, p.XrayInboundTag, p.XrayProtocol, exp, p.MaxConnections, "", b.cfg.XrayPublicHost)
		if err != nil {
			log.Printf("[bot] fulfill xray: %v", err)
			b.notify(txn.TelegramID, "❌ Pagamento aprovado, mas houve um erro ao criar a conta Xray. Contate o suporte.")
			return
		}
		_ = b.store.SetTransactionTarget(b.ctx, txn.ID, uuid)
		b.notify(txn.TelegramID, b.formatXrayDelivery(p.Name, uuid, link, exp))
		return
	}
	user := genUsername("ssh")
	pass := genPassword()
	if err := createSSHUser(b.ctx, b.store, user, pass, exp, p.MaxConnections, p.LimitMbpsUp, p.LimitMbpsDown, ""); err != nil {
		log.Printf("[bot] fulfill ssh: %v", err)
		b.notify(txn.TelegramID, "❌ Pagamento aprovado, mas houve um erro ao criar a conta SSH. Contate o suporte.")
		return
	}
	_ = b.store.SetTransactionTarget(b.ctx, txn.ID, user)
	b.notify(txn.TelegramID, b.formatSSHDelivery(p.Name, user, pass, exp))
}

func (b *Bot) fulfillRenewal(txn *BotTransaction) {
	if txn.PlanID == nil || txn.RenewTarget == "" {
		return
	}
	p, err := b.store.GetPlan(b.ctx, *txn.PlanID)
	if err != nil {
		return
	}
	parts := strings.SplitN(txn.RenewTarget, ":", 2)
	if len(parts) < 2 {
		return
	}
	kind, id := parts[0], parts[1]
	base := time.Now()
	add := time.Duration(p.Days) * 24 * time.Hour

	if kind == "x" {
		newExp := base.Add(add)
		if meta, err := b.store.GetXrayClientMeta(b.ctx, id); err == nil && meta.ExpiresAt != nil && meta.ExpiresAt.After(base) {
			newExp = meta.ExpiresAt.Add(add)
		}
		if err := renewXrayClient(b.ctx, b.store, id, newExp); err != nil {
			log.Printf("[bot] renew xray %s: %v", id, err)
			b.notify(txn.TelegramID, "❌ Pagamento aprovado, mas houve um erro ao renovar. Contate o suporte.")
			return
		}
		_ = b.store.SetTransactionTarget(b.ctx, txn.ID, id)
		b.notify(txn.TelegramID, fmt.Sprintf("✅ <b>%s</b> renovado!\n⚡ Xray <code>%s</code>\nNova validade: %s",
			htmlEscape(p.Name), htmlEscape(id), newExp.Format("02/01/2006 15:04")))
		return
	}

	newExp := base.Add(add)
	if u, ok := userMgr.Get(id); ok && u.ExpiresAt != nil && u.ExpiresAt.After(base) {
		newExp = u.ExpiresAt.Add(add)
	}
	if err := renewSSHUser(b.ctx, b.store, id, newExp); err != nil {
		log.Printf("[bot] renew ssh %s: %v", id, err)
		b.notify(txn.TelegramID, "❌ Pagamento aprovado, mas houve um erro ao renovar. Contate o suporte.")
		return
	}
	_ = b.store.SetTransactionTarget(b.ctx, txn.ID, id)
	b.notify(txn.TelegramID, fmt.Sprintf("✅ <b>%s</b> renovado!\n🔒 SSH <code>%s</code>\nNova validade: %s",
		htmlEscape(p.Name), htmlEscape(id), newExp.Format("02/01/2006 15:04")))
}

// ---------- "Verificar" button ----------

func (b *Bot) checkPaymentButton(chatID int64, from *tgUser, txnIDStr string) {
	id, _ := strconv.Atoi(txnIDStr)
	txn, err := b.store.GetTransaction(b.ctx, id)
	if err != nil {
		b.send(chatID, "Pagamento não encontrado.", backKeyboard())
		return
	}
	if txn.TelegramID != from.ID {
		b.send(chatID, "Pagamento inválido.", backKeyboard())
		return
	}
	switch txn.Status {
	case "approved":
		b.send(chatID, "✅ Pagamento já confirmado! Veja em 🛍️ Minhas Compras.", backKeyboard())
		return
	case "expired":
		b.send(chatID, "⌛ Este PIX expirou. Gere um novo pagamento.", backKeyboard())
		return
	case "refunded":
		b.send(chatID, "Este pagamento foi estornado.", backKeyboard())
		return
	}
	if b.mp == nil {
		b.send(chatID, "Pagamento não configurado.", backKeyboard())
		return
	}
	status, err := b.mp.GetPaymentStatus(b.ctx, txn.MPPaymentID)
	if err != nil {
		b.send(chatID, "Não foi possível verificar agora. Tente novamente em instantes.", backKeyboard())
		return
	}
	if status == "approved" {
		b.tryFulfill(txn.ID) // delivers via notify
		return
	}
	b.send(chatID, "⏱ Pagamento ainda não identificado. Assim que cair, a liberação é automática.",
		kb([]tgInlineButton{btn("🔄 Verificar novamente", "pay:check:"+botItoa(txn.ID)), btn("⬅️ Voltar", "menu:main")}))
}
