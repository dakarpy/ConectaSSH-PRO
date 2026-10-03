package main

// bot_core.go — Bot lifecycle, Telegram update dispatch, and shared helpers.

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"
)

// Global bot instance (nil when disabled). Guarded by botMgrMu.
var (
	botMgr   *Bot
	botMgrMu sync.Mutex
)

func currentBot() *Bot {
	botMgrMu.Lock()
	defer botMgrMu.Unlock()
	return botMgr
}

type Bot struct {
	store  *Store
	cfg    *BotConfig
	tg     *tgClient
	mp     *mpClient
	ctx    context.Context
	cancel context.CancelFunc
}

func newBot(store *Store, cfg *BotConfig) *Bot {
	ctx, cancel := context.WithCancel(context.Background())
	b := &Bot{
		store:  store,
		cfg:    cfg,
		tg:     newTGClient(cfg.TelegramToken),
		ctx:    ctx,
		cancel: cancel,
	}
	if cfg.MPAccessToken != "" {
		b.mp = newMPClient(cfg.MPAccessToken)
	}
	return b
}

// ---------- Lifecycle (called from main.go boot and bot_api.go on save) ----------

// startBotService loads config from the DB and starts the bot if enabled.
func startBotService(store *Store) {
	if store == nil {
		return
	}
	cfg, err := LoadBotConfig(context.Background(), store)
	if err != nil {
		log.Printf("[bot] load config: %v", err)
		return
	}
	botMgrMu.Lock()
	defer botMgrMu.Unlock()
	if botMgr != nil {
		botMgr.cancel()
		botMgr = nil
	}
	if !cfg.Enabled {
		log.Printf("[bot] disabled")
		return
	}
	if cfg.TelegramToken == "" {
		log.Printf("[bot] enabled but no telegram token configured; not starting")
		return
	}
	b := newBot(store, cfg)
	botMgr = b
	b.start()
}

// reloadBotService restarts the bot after a config change.
func reloadBotService(store *Store) { startBotService(store) }

func (b *Bot) start() {
	log.Printf("[bot] starting (telegram=long-polling, mp_confirm=%s)", b.cfg.MPConfirmMode)
	// Telegram uses long-polling only. Clearing any stale webhook + polling both
	// hit the network, so run off the goroutine that holds botMgrMu.
	go func() {
		_ = b.tg.deleteWebhook(b.ctx)
		b.runPolling()
	}()
	if b.mp != nil && b.cfg.MPConfirmMode == "polling" {
		go b.runPaymentPoller()
	}
}

func (b *Bot) stop() { b.cancel() }

// ---------- Update polling ----------

func (b *Bot) runPolling() {
	var offset int64
	log.Printf("[bot] long-polling started")
	for {
		select {
		case <-b.ctx.Done():
			log.Printf("[bot] polling stopped")
			return
		default:
		}
		ups, err := b.tg.getUpdates(b.ctx, offset, 50)
		if err != nil {
			if b.ctx.Err() != nil {
				return
			}
			log.Printf("[bot] getUpdates: %v", err)
			time.Sleep(3 * time.Second)
			continue
		}
		for i := range ups {
			u := ups[i]
			if u.UpdateID >= offset {
				offset = u.UpdateID + 1
			}
			b.handleUpdate(&u)
		}
	}
}

// ---------- Dispatch ----------

func (b *Bot) handleUpdate(u *tgUpdate) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[bot] panic handling update: %v", r)
		}
	}()
	switch {
	case u.CallbackQuery != nil:
		b.handleCallback(u.CallbackQuery)
	case u.Message != nil && u.Message.From != nil:
		b.handleMessage(u.Message)
	}
}

func (b *Bot) handleMessage(m *tgMessage) {
	b.touchUser(m.From)
	text := strings.TrimSpace(m.Text)
	switch {
	case text == "/start" || text == "/menu" || text == "start":
		b.showMainMenu(m.Chat.ID, m.From, 0)
	case strings.HasPrefix(text, "/stats") && b.cfg.isAdmin(m.From.ID):
		b.cmdAdminStats(m.Chat.ID)
	case strings.HasPrefix(text, "/addcredit") && b.cfg.isAdmin(m.From.ID):
		b.cmdAdminAddCredit(m.Chat.ID, text)
	default:
		b.showMainMenu(m.Chat.ID, m.From, 0)
	}
}

func (b *Bot) handleCallback(cb *tgCallbackQuery) {
	b.touchUser(&cb.From)
	_ = b.tg.answerCallback(b.ctx, cb.ID, "")
	if cb.Message == nil {
		return
	}
	chatID := cb.Message.Chat.ID
	msgID := cb.Message.MessageID
	data := cb.Data

	switch {
	case data == "menu:main":
		b.showMainMenu(chatID, &cb.From, msgID)
	case data == "buy":
		b.showPlanList(chatID, msgID, "ssh_or_xray", "buy")
	case strings.HasPrefix(data, "buy:"):
		b.startPlanPurchase(chatID, &cb.From, data[len("buy:"):], false)
	case data == "renew":
		b.showRenewList(chatID, &cb.From, msgID)
	case strings.HasPrefix(data, "renew:"):
		b.startRenew(chatID, &cb.From, msgID, data[len("renew:"):])
	case strings.HasPrefix(data, "rnw:"):
		b.startRenewPayment(chatID, &cb.From, data[len("rnw:"):])
	case data == "trial":
		b.handleTrial(chatID, &cb.From)
	case data == "purchases":
		b.showPurchases(chatID, &cb.From, msgID)
	case data == "app":
		b.showText(chatID, msgID, "app_text", "📥 App: (configure em bot_settings)")
	case data == "contact":
		b.showText(chatID, msgID, "contact_text", "👤 Contato: (configure em bot_settings)")
	case data == "res:menu":
		b.showResellerMenu(chatID, &cb.From, msgID)
	case data == "res:topup":
		b.showCreditPackages(chatID, msgID)
	case strings.HasPrefix(data, "res:topup:"):
		b.startTopup(chatID, &cb.From, data[len("res:topup:"):])
	case data == "res:create":
		b.showPlanList(chatID, msgID, "ssh_or_xray", "res:create")
	case strings.HasPrefix(data, "res:create:"):
		b.resellerCreateAccount(chatID, &cb.From, data[len("res:create:"):])
	case data == "res:clients":
		b.showResellerClients(chatID, &cb.From, msgID)
	case strings.HasPrefix(data, "pay:check:"):
		b.checkPaymentButton(chatID, &cb.From, data[len("pay:check:"):])
	default:
		// unknown — refresh menu
		b.showMainMenu(chatID, &cb.From, msgID)
	}
}

// ---------- User helpers ----------

func (b *Bot) touchUser(u *tgUser) {
	if u == nil {
		return
	}
	_ = b.store.UpsertBotUser(b.ctx, &BotUser{
		TelegramID: u.ID,
		Username:   u.Username,
		FirstName:  u.FirstName,
	})
}

func (b *Bot) botUser(telegramID int64) *BotUser {
	u, err := b.store.GetBotUser(b.ctx, telegramID)
	if err != nil {
		return &BotUser{TelegramID: telegramID, Role: "customer"}
	}
	return u
}

// ---------- Message helpers ----------

func (b *Bot) send(chatID int64, text string, kb *tgInlineKeyboard) {
	if _, err := b.tg.sendMessage(b.ctx, chatID, text, kb); err != nil {
		log.Printf("[bot] sendMessage: %v", err)
	}
}

// sendOrEdit edits an existing message if msgID>0, else sends a new one.
func (b *Bot) sendOrEdit(chatID, msgID int64, text string, kb *tgInlineKeyboard) {
	if msgID > 0 {
		if err := b.tg.editMessageText(b.ctx, chatID, msgID, text, kb); err == nil {
			return
		}
	}
	b.send(chatID, text, kb)
}

func (b *Bot) showText(chatID, msgID int64, key, def string) {
	txt := b.store.GetSetting(b.ctx, key, def)
	b.sendOrEdit(chatID, msgID, txt, backKeyboard())
}

// ---------- Keyboard builders ----------

func kb(rows ...[]tgInlineButton) *tgInlineKeyboard {
	return &tgInlineKeyboard{InlineKeyboard: rows}
}

func btn(text, data string) tgInlineButton { return tgInlineButton{Text: text, CallbackData: data} }

func urlBtn(text, u string) tgInlineButton { return tgInlineButton{Text: text, URL: u} }

func backKeyboard() *tgInlineKeyboard {
	return kb([]tgInlineButton{btn("⬅️ Voltar", "menu:main")})
}
