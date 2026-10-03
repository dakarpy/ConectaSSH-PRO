package main

// bot_flows.go — customer + reseller conversation flows and admin commands.

import (
	"encoding/base64"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"
)

// ---------- Main menu ----------

func (b *Bot) showMainMenu(chatID int64, from *tgUser, msgID int64) {
	bu := b.botUser(from.ID)
	if bu.Role == "blocked" {
		b.sendOrEdit(chatID, msgID, "🚫 Seu acesso foi bloqueado.", nil)
		return
	}
	welcome := b.store.GetSetting(b.ctx, "welcome_text", "")
	var text string
	if welcome != "" {
		text = strings.ReplaceAll(welcome, "{name}", htmlEscape(from.FirstName))
	} else {
		text = fmt.Sprintf("😉 Olá <b>%s</b>, seja bem-vindo!\n\n🚀 Aqui você encontra os melhores planos <b>SSH</b> e <b>Xray</b> Premium.\nSelecione uma das opções abaixo:", htmlEscape(from.FirstName))
	}

	var rows [][]tgInlineButton
	if b.cfg.TrialEnabled {
		rows = append(rows, []tgInlineButton{btn("⏳ Teste Grátis", "trial"), btn("🛍️ Minhas Compras", "purchases")})
	} else {
		rows = append(rows, []tgInlineButton{btn("🛍️ Minhas Compras", "purchases")})
	}
	rows = append(rows, []tgInlineButton{btn("💎 Comprar Premium", "buy")})
	rows = append(rows, []tgInlineButton{btn("🔄 Renovar", "renew")})

	appURL := b.store.GetSetting(b.ctx, "app_url", "")
	appRow := []tgInlineButton{}
	if appURL != "" {
		appRow = append(appRow, urlBtn("📥 Baixar APP", appURL))
	} else {
		appRow = append(appRow, btn("📥 Baixar APP", "app"))
	}
	appRow = append(appRow, btn("👤 Contato", "contact"))
	rows = append(rows, appRow)

	if bu.Role == "reseller" {
		rows = append(rows, []tgInlineButton{btn("👑 Área do Revendedor", "res:menu")})
	}
	b.sendOrEdit(chatID, msgID, text, kb(rows...))
}

// ---------- Plan list (buy / reseller create) ----------

func (b *Bot) showPlanList(chatID, msgID int64, _ string, action string) {
	plans, err := b.store.ListPlans(b.ctx, true)
	if err != nil || len(plans) == 0 {
		b.sendOrEdit(chatID, msgID, "Nenhum plano disponível no momento.", backKeyboard())
		return
	}
	isReseller := action == "res:create"
	var rows [][]tgInlineButton
	for _, p := range plans {
		icon := "🔒"
		if p.Kind == "xray" {
			icon = "⚡"
		}
		var label string
		if isReseller {
			label = fmt.Sprintf("%s %s — %d créd.", icon, p.Name, p.CreditCost)
		} else {
			label = fmt.Sprintf("%s %s — %s", icon, p.Name, centsToBRL(p.PriceCents))
		}
		rows = append(rows, []tgInlineButton{btn(label, action+":"+botItoa(p.ID))})
	}
	rows = append(rows, []tgInlineButton{btn("⬅️ Voltar", backTarget(action))})
	title := "💎 Escolha um plano:"
	if isReseller {
		title = "➕ Escolha um plano para criar (custo em créditos):"
	}
	b.sendOrEdit(chatID, msgID, title, kb(rows...))
}

func backTarget(action string) string {
	if strings.HasPrefix(action, "res:") {
		return "res:menu"
	}
	return "menu:main"
}

// ---------- Buy ----------

func (b *Bot) startPlanPurchase(chatID int64, from *tgUser, planIDStr string, _ bool) {
	id, _ := strconv.Atoi(planIDStr)
	p, err := b.store.GetPlan(b.ctx, id)
	if err != nil {
		b.send(chatID, "Plano não encontrado.", backKeyboard())
		return
	}
	pid := p.ID
	b.createAndSendPix(chatID, from, "plan_purchase", "Compra: "+p.Name, p.PriceCents, &pid, nil, 0, "")
}

// ---------- Renew ----------

func (b *Bot) showRenewList(chatID int64, from *tgUser, msgID int64) {
	txns, _ := b.store.ListUserTransactions(b.ctx, from.ID, 100)
	seen := map[string]bool{}
	var rows [][]tgInlineButton
	for _, t := range txns {
		if t.Status != "approved" || t.TargetUsername == "" || t.PlanID == nil {
			continue
		}
		p, err := b.store.GetPlan(b.ctx, *t.PlanID)
		if err != nil {
			continue
		}
		key := p.Kind + ":" + t.TargetUsername
		if seen[key] {
			continue
		}
		seen[key] = true
		short := "s"
		if p.Kind == "xray" {
			short = "x"
		}
		disp := t.TargetUsername
		if len(disp) > 16 {
			disp = disp[:8] + "…"
		}
		rows = append(rows, []tgInlineButton{btn("🔄 "+disp+" ("+p.Kind+")", "renew:"+short+":"+t.TargetUsername)})
	}
	if len(rows) == 0 {
		b.sendOrEdit(chatID, msgID, "Você não tem contas para renovar.", backKeyboard())
		return
	}
	rows = append(rows, []tgInlineButton{btn("⬅️ Voltar", "menu:main")})
	b.sendOrEdit(chatID, msgID, "🔄 Selecione a conta para renovar:", kb(rows...))
}

func (b *Bot) startRenew(chatID int64, from *tgUser, msgID int64, target string) {
	kind := "ssh"
	if strings.HasPrefix(target, "x:") {
		kind = "xray"
	}
	plans, _ := b.store.ListPlans(b.ctx, true)
	var rows [][]tgInlineButton
	for _, p := range plans {
		if p.Kind != kind {
			continue
		}
		label := fmt.Sprintf("%s — %s", p.Name, centsToBRL(p.PriceCents))
		rows = append(rows, []tgInlineButton{btn(label, "rnw:"+botItoa(p.ID)+":"+target)})
	}
	if len(rows) == 0 {
		b.sendOrEdit(chatID, msgID, "Nenhum plano de renovação disponível.", backKeyboard())
		return
	}
	rows = append(rows, []tgInlineButton{btn("⬅️ Voltar", "renew")})
	b.sendOrEdit(chatID, msgID, "🔄 Escolha a duração da renovação:", kb(rows...))
}

func (b *Bot) startRenewPayment(chatID int64, from *tgUser, payload string) {
	parts := strings.SplitN(payload, ":", 3)
	if len(parts) < 3 {
		b.send(chatID, "Renovação inválida.", backKeyboard())
		return
	}
	id, _ := strconv.Atoi(parts[0])
	renewTarget := parts[1] + ":" + parts[2] // "s:username" or "x:uuid"
	p, err := b.store.GetPlan(b.ctx, id)
	if err != nil {
		b.send(chatID, "Plano não encontrado.", backKeyboard())
		return
	}
	pid := p.ID
	b.createAndSendPix(chatID, from, "plan_renewal", "Renovação: "+p.Name, p.PriceCents, &pid, nil, 0, renewTarget)
}

// ---------- Trial ----------

func (b *Bot) handleTrial(chatID int64, from *tgUser) {
	if !b.cfg.TrialEnabled {
		b.send(chatID, "Teste grátis indisponível.", backKeyboard())
		return
	}
	bu := b.botUser(from.ID)
	if bu.TrialUsed {
		b.send(chatID, "⚠️ Você já utilizou seu teste grátis.", backKeyboard())
		return
	}
	exp := time.Now().Add(time.Duration(b.cfg.TrialHours) * time.Hour)
	if b.cfg.TrialKind == "xray" {
		uuid, link, err := createXrayClient(b.ctx, b.store, b.cfg.TrialInboundTag, "", exp, b.cfg.TrialMaxConnections, "", b.cfg.XrayPublicHost)
		if err != nil {
			log.Printf("[bot] trial xray: %v", err)
			b.send(chatID, "❌ Falha ao criar teste. Tente mais tarde.", backKeyboard())
			return
		}
		_ = b.store.SetBotUserTrialUsed(b.ctx, from.ID)
		b.send(chatID, b.formatXrayDelivery("Teste Grátis", uuid, link, exp), backKeyboard())
		return
	}
	user := genUsername("test")
	pass := genPassword()
	if err := createSSHUser(b.ctx, b.store, user, pass, exp, b.cfg.TrialMaxConnections, 0, 0, ""); err != nil {
		log.Printf("[bot] trial ssh: %v", err)
		b.send(chatID, "❌ Falha ao criar teste. Tente mais tarde.", backKeyboard())
		return
	}
	_ = b.store.SetBotUserTrialUsed(b.ctx, from.ID)
	b.send(chatID, b.formatSSHDelivery("Teste Grátis", user, pass, exp), backKeyboard())
}

// ---------- Purchases ----------

func (b *Bot) showPurchases(chatID int64, from *tgUser, msgID int64) {
	txns, _ := b.store.ListUserTransactions(b.ctx, from.ID, 20)
	var sb strings.Builder
	sb.WriteString("🛍️ <b>Suas Compras</b>\n\n")
	count := 0
	for _, t := range txns {
		if t.Status == "pending" {
			continue
		}
		count++
		sb.WriteString(fmt.Sprintf("• #%d %s — %s — %s\n", t.ID, txnTypeLabel(t.Type), centsToBRL(t.AmountCents), statusLabel(t.Status)))
		if t.TargetUsername != "" && t.Status == "approved" {
			sb.WriteString("   conta: <code>" + htmlEscape(t.TargetUsername) + "</code>\n")
		}
	}
	if count == 0 {
		sb.WriteString("Nenhuma compra ainda.")
	}
	b.sendOrEdit(chatID, msgID, sb.String(), backKeyboard())
}

// ---------- Reseller ----------

func (b *Bot) showResellerMenu(chatID int64, from *tgUser, msgID int64) {
	bu := b.botUser(from.ID)
	if bu.Role != "reseller" {
		b.sendOrEdit(chatID, msgID, "Você não é um revendedor.", backKeyboard())
		return
	}
	text := fmt.Sprintf("👑 <b>Área do Revendedor</b>\n\n💳 Saldo: <b>%d créditos</b>", bu.CreditBalance)
	rows := [][]tgInlineButton{
		{btn("💳 Recarregar Créditos", "res:topup")},
		{btn("➕ Criar Conta", "res:create")},
		{btn("👥 Meus Clientes", "res:clients")},
		{btn("⬅️ Voltar", "menu:main")},
	}
	b.sendOrEdit(chatID, msgID, text, kb(rows...))
}

func (b *Bot) showCreditPackages(chatID, msgID int64) {
	pkgs, _ := b.store.ListCreditPackages(b.ctx, true)
	if len(pkgs) == 0 {
		b.sendOrEdit(chatID, msgID, "Nenhum pacote de créditos disponível.", kb([]tgInlineButton{btn("⬅️ Voltar", "res:menu")}))
		return
	}
	var rows [][]tgInlineButton
	for _, p := range pkgs {
		rows = append(rows, []tgInlineButton{btn(fmt.Sprintf("%s — %d créd. — %s", p.Name, p.Credits, centsToBRL(p.PriceCents)), "res:topup:"+botItoa(p.ID))})
	}
	rows = append(rows, []tgInlineButton{btn("⬅️ Voltar", "res:menu")})
	b.sendOrEdit(chatID, msgID, "💳 Escolha um pacote de créditos:", kb(rows...))
}

func (b *Bot) startTopup(chatID int64, from *tgUser, pkgIDStr string) {
	id, _ := strconv.Atoi(pkgIDStr)
	p, err := b.store.GetCreditPackage(b.ctx, id)
	if err != nil {
		b.send(chatID, "Pacote não encontrado.", backKeyboard())
		return
	}
	pid := p.ID
	b.createAndSendPix(chatID, from, "credit_topup", "Recarga: "+p.Name, p.PriceCents, nil, &pid, p.Credits, "")
}

func (b *Bot) resellerCreateAccount(chatID int64, from *tgUser, planIDStr string) {
	bu := b.botUser(from.ID)
	if bu.Role != "reseller" || bu.LinkedAdminUsername == "" {
		b.send(chatID, "Conta de revendedor não configurada.", backKeyboard())
		return
	}
	id, _ := strconv.Atoi(planIDStr)
	p, err := b.store.GetPlan(b.ctx, id)
	if err != nil {
		b.send(chatID, "Plano não encontrado.", backKeyboard())
		return
	}
	if bu.CreditBalance < p.CreditCost {
		b.send(chatID, fmt.Sprintf("❌ Saldo insuficiente. Necessário %d créditos, você tem %d.", p.CreditCost, bu.CreditBalance),
			kb([]tgInlineButton{btn("💳 Recarregar", "res:topup"), btn("⬅️ Voltar", "res:menu")}))
		return
	}
	if owner, ok := adminUsers.get(bu.LinkedAdminUsername); ok && owner.MaxUsers > 0 &&
		countOwnedQuota(b.ctx, b.store, bu.LinkedAdminUsername) >= owner.MaxUsers {
		b.send(chatID, fmt.Sprintf("❌ Limite de contas atingido (%d).", owner.MaxUsers), backKeyboard())
		return
	}
	// Debit first; refund if provisioning fails.
	if _, err := b.store.AdjustCredits(b.ctx, from.ID, -p.CreditCost, "account_create", nil); err != nil {
		b.send(chatID, "❌ Não foi possível debitar créditos.", backKeyboard())
		return
	}
	exp := time.Now().Add(time.Duration(p.Days) * 24 * time.Hour)
	var deliver string
	if p.Kind == "xray" {
		uuid, link, err := createXrayClient(b.ctx, b.store, p.XrayInboundTag, p.XrayProtocol, exp, p.MaxConnections, bu.LinkedAdminUsername, b.cfg.XrayPublicHost)
		if err != nil {
			_, _ = b.store.AdjustCredits(b.ctx, from.ID, p.CreditCost, "refund", nil)
			b.send(chatID, "❌ Falha ao criar conta Xray. Créditos devolvidos.", backKeyboard())
			return
		}
		deliver = b.formatXrayDelivery(p.Name, uuid, link, exp)
	} else {
		user := genUsername("r")
		pass := genPassword()
		if err := createSSHUser(b.ctx, b.store, user, pass, exp, p.MaxConnections, p.LimitMbpsUp, p.LimitMbpsDown, bu.LinkedAdminUsername); err != nil {
			_, _ = b.store.AdjustCredits(b.ctx, from.ID, p.CreditCost, "refund", nil)
			b.send(chatID, "❌ Falha ao criar conta SSH. Créditos devolvidos.", backKeyboard())
			return
		}
		deliver = b.formatSSHDelivery(p.Name, user, pass, exp)
	}
	b.send(chatID, deliver+fmt.Sprintf("\n\n💳 Saldo restante: %d créditos", bu.CreditBalance-p.CreditCost),
		kb([]tgInlineButton{btn("➕ Criar outra", "res:create"), btn("⬅️ Voltar", "res:menu")}))
}

func (b *Bot) showResellerClients(chatID int64, from *tgUser, msgID int64) {
	bu := b.botUser(from.ID)
	if bu.Role != "reseller" || bu.LinkedAdminUsername == "" {
		b.sendOrEdit(chatID, msgID, "Conta de revendedor não configurada.", backKeyboard())
		return
	}
	var sb strings.Builder
	sb.WriteString("👥 <b>Seus Clientes</b>\n\n")
	n := 0
	for _, u := range userMgr.List() {
		if u.Cfg.OwnerUsername == bu.LinkedAdminUsername {
			n++
			exp := "sem validade"
			if u.ExpiresAt != nil {
				exp = u.ExpiresAt.Format("02/01/2006")
			}
			sb.WriteString(fmt.Sprintf("• SSH <code>%s</code> — %s\n", htmlEscape(u.Cfg.Username), exp))
			if n >= 40 {
				break
			}
		}
	}
	xs, _ := b.store.ListXrayClientsByOwner(b.ctx, bu.LinkedAdminUsername)
	for _, x := range xs {
		n++
		exp := "sem validade"
		if x.ExpiresAt != nil {
			exp = x.ExpiresAt.Format("02/01/2006")
		}
		sb.WriteString(fmt.Sprintf("• Xray <code>%s</code> — %s\n", htmlEscape(x.UUID), exp))
		if n >= 80 {
			break
		}
	}
	if n == 0 {
		sb.WriteString("Nenhum cliente ainda.")
	}
	b.sendOrEdit(chatID, msgID, sb.String(), kb([]tgInlineButton{btn("⬅️ Voltar", "res:menu")}))
}

// ---------- PIX charge creation + delivery formatting ----------

func (b *Bot) createAndSendPix(chatID int64, from *tgUser, ttype, description string, amountCents int, planID, pkgID *int, credits int, renewTarget string) {
	if amountCents <= 0 {
		b.send(chatID, "❌ Este item não tem preço configurado. Fale com o suporte.", backKeyboard())
		return
	}
	if b.mp == nil {
		b.send(chatID, "❌ Pagamento não configurado no momento. Fale com o suporte.", backKeyboard())
		return
	}
	exp := time.Now().Add(time.Duration(b.cfg.PixExpirationMinutes) * time.Minute)
	pix, err := b.mp.CreatePixPayment(b.ctx, amountCents, description, "", strconv.FormatInt(from.ID, 10), exp, uuidV4())
	if err != nil {
		log.Printf("[bot] create pix: %v", err)
		b.send(chatID, "❌ Falha ao gerar o pagamento PIX. Tente novamente em instantes.", backKeyboard())
		return
	}
	txn := &BotTransaction{
		TelegramID:  from.ID,
		Type:        ttype,
		PlanID:      planID,
		PackageID:   pkgID,
		Credits:     credits,
		AmountCents: amountCents,
		MPPaymentID: pix.PaymentID,
		MPQRCode:    pix.QRCode,
		MPQRBase64:  pix.QRBase64,
		Status:      "pending",
		RenewTarget: renewTarget,
		ExpiresAt:   &exp,
	}
	if err := b.store.CreateTransaction(b.ctx, txn); err != nil {
		log.Printf("[bot] create txn: %v", err)
		b.send(chatID, "❌ Erro interno ao registrar o pagamento.", backKeyboard())
		return
	}
	b.sendPixMessage(chatID, txn, description)
}

func (b *Bot) sendPixMessage(chatID int64, txn *BotTransaction, description string) {
	caption := fmt.Sprintf("💳 <b>Pagamento PIX</b>\n%s\nValor: <b>%s</b>\n⏱ Validade: %d min\n\nEscaneie o QR acima ou use o código copia-e-cola abaixo. A liberação é automática após o pagamento.",
		htmlEscape(description), centsToBRL(txn.AmountCents), b.cfg.PixExpirationMinutes)
	kbd := kb(
		[]tgInlineButton{btn("✅ Já paguei / Verificar", "pay:check:"+botItoa(txn.ID))},
		[]tgInlineButton{btn("⬅️ Voltar", "menu:main")},
	)
	sent := false
	if txn.MPQRBase64 != "" {
		if raw, err := base64.StdEncoding.DecodeString(txn.MPQRBase64); err == nil {
			if _, err := b.tg.sendPhotoBytes(b.ctx, chatID, raw, "pix.png", caption, kbd); err == nil {
				sent = true
			}
		}
	}
	if !sent {
		b.send(chatID, caption, kbd)
	}
	if txn.MPQRCode != "" {
		b.send(chatID, "📋 <b>PIX Copia e Cola:</b>\n<code>"+htmlEscape(txn.MPQRCode)+"</code>", nil)
	}
}

func (b *Bot) formatSSHDelivery(planName, user, pass string, exp time.Time) string {
	host := b.cfg.PublicHost
	if host == "" {
		host = "(configure o host no painel)"
	}
	return fmt.Sprintf("✅ <b>%s</b>\n\n🔒 <b>Conta SSH</b>\nHost: <code>%s</code>\nUsuário: <code>%s</code>\nSenha: <code>%s</code>\nValidade: %s",
		htmlEscape(planName), htmlEscape(host), htmlEscape(user), htmlEscape(pass), exp.Format("02/01/2006 15:04"))
}

func (b *Bot) formatXrayDelivery(planName, uuid, link string, exp time.Time) string {
	return fmt.Sprintf("✅ <b>%s</b>\n\n⚡ <b>Conta Xray</b>\nUUID: <code>%s</code>\nValidade: %s\n\n🔗 Link de conexão:\n<code>%s</code>",
		htmlEscape(planName), htmlEscape(uuid), exp.Format("02/01/2006 15:04"), htmlEscape(link))
}

// ---------- Admin commands (in-chat convenience) ----------

func (b *Bot) cmdAdminStats(chatID int64) {
	users, _ := b.store.ListBotUsers(b.ctx)
	pend, _ := b.store.ListPendingTransactions(b.ctx)
	b.send(chatID, fmt.Sprintf("📊 <b>Estatísticas</b>\nUsuários do bot: %d\nPagamentos pendentes: %d\nContas SSH ativas: %d",
		len(users), len(pend), len(userMgr.List())), nil)
}

func (b *Bot) cmdAdminAddCredit(chatID int64, text string) {
	f := strings.Fields(text)
	if len(f) < 3 {
		b.send(chatID, "Uso: /addcredit &lt;telegram_id&gt; &lt;quantidade&gt;", nil)
		return
	}
	tid, _ := strconv.ParseInt(f[1], 10, 64)
	amt, _ := strconv.Atoi(f[2])
	bal, err := b.store.AdjustCredits(b.ctx, tid, amt, "admin_adjust", nil)
	if err != nil {
		b.send(chatID, "Erro: "+err.Error(), nil)
		return
	}
	b.send(chatID, fmt.Sprintf("✅ Ajuste aplicado. Novo saldo de %d: %d créditos", tid, bal), nil)
	b.notify(tid, fmt.Sprintf("💳 Seu saldo foi ajustado em %+d créditos. Saldo atual: %d", amt, bal))
}

func (b *Bot) notify(telegramID int64, text string) {
	if _, err := b.tg.sendMessage(b.ctx, telegramID, text, nil); err != nil {
		log.Printf("[bot] notify %d: %v", telegramID, err)
	}
}

// ---------- labels ----------

func txnTypeLabel(t string) string {
	switch t {
	case "plan_purchase":
		return "Compra"
	case "plan_renewal":
		return "Renovação"
	case "credit_topup":
		return "Recarga"
	}
	return t
}

func statusLabel(s string) string {
	switch s {
	case "approved":
		return "✅ pago"
	case "pending":
		return "⏳ pendente"
	case "expired":
		return "⌛ expirado"
	case "refunded":
		return "↩️ estornado"
	case "error":
		return "❌ erro"
	}
	return s
}
