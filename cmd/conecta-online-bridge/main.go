package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	configPath = "/opt/myapp/config.json"
	localURL   = "http://127.0.0.1:9090/api/online/listall.php"
	loopActive = 2 * time.Second
	loopIdle   = 10 * time.Second
)

type cfg struct {
	APIToken string `json:"api_token"`
	Domain   string `json:"domain"`
}

type localSession struct {
	Login      string `json:"login"`
	Tipo       string `json:"tipo"`
	IP         string `json:"ip"`
	StartTime  string `json:"start_time"`
	Dono       string `json:"dono"`
	Transporte string `json:"transporte"`
}

type onlineUser struct {
	Login    string `json:"login"`
	Tipo     string `json:"tipo"`
	RootUser string `json:"rootuser"`
	IPv4     string `json:"ipv4"`
	IPv6     string `json:"ipv6"`
	Data     string `json:"data"`
	Token    string `json:"token"`
	ID       string `json:"id"`
	Email    string `json:"email"`
}

type reportPayload struct {
	IPv4     string       `json:"ipv4"`
	Usuarios []onlineUser `json:"usuarios"`
}

var (
	publicIPMu sync.Mutex
	publicIP   string
	publicIPAt time.Time
)

func loadCfg() (cfg, bool) {
	b, err := os.ReadFile(configPath)
	if err != nil {
		return cfg{}, false
	}
	var c cfg
	if json.Unmarshal(b, &c) != nil {
		return cfg{}, false
	}
	c.APIToken = strings.TrimSpace(c.APIToken)
	c.Domain = strings.TrimSpace(c.Domain)
	return c, c.APIToken != "" && c.Domain != ""
}

func getPublicIP(client *http.Client) string {
	publicIPMu.Lock()
	defer publicIPMu.Unlock()
	if publicIP != "" && time.Since(publicIPAt) < 5*time.Minute {
		return publicIP
	}
	req, err := http.NewRequest(http.MethodGet, "https://api.ipify.org?format=json", nil)
	if err != nil {
		return publicIP
	}
	resp, err := client.Do(req)
	if err != nil {
		return publicIP
	}
	defer resp.Body.Close()
	var v struct {
		IP string `json:"ip"`
	}
	if resp.StatusCode == http.StatusOK &&
		json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&v) == nil &&
		strings.TrimSpace(v.IP) != "" {
		publicIP = strings.TrimSpace(v.IP)
		publicIPAt = time.Now()
	}
	return publicIP
}

func main() {
	log.SetFlags(log.LstdFlags)
	client := &http.Client{Timeout: 15 * time.Second}

	for {
		c, configured := loadCfg()
		if !configured {
			time.Sleep(loopIdle)
			continue
		}
		report(client, c)
		time.Sleep(loopActive)
	}
}

func report(client *http.Client, c cfg) {
	req, err := http.NewRequest(http.MethodGet, localURL, nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("local online: %v", err)
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		return
	}

	var sessions []localSession
	if err := json.Unmarshal(body, &sessions); err != nil {
		log.Printf("local online JSON: %v", err)
		return
	}

	users := make([]onlineUser, 0, len(sessions))
	for _, s := range sessions {
		ip := strings.TrimSpace(s.IP)
		if host, _, e := net.SplitHostPort(ip); e == nil {
			ip = host
		}
		transport := strings.TrimSpace(s.Transporte)
		if transport == "" {
			transport = strings.TrimSpace(s.Tipo)
		}
		users = append(users, onlineUser{
			Login:    s.Login,
			Tipo:     strings.ToLower(transport),
			RootUser: s.Dono,
			IPv4:     ip,
			Data:     s.StartTime,
			ID:       s.Login,
		})
	}

	payload := reportPayload{IPv4: getPublicIP(client), Usuarios: users}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}

	req, err = http.NewRequest(http.MethodPost, c.Domain, bytes.NewReader(data))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIToken)

	remote, err := client.Do(req)
	if err != nil {
		log.Printf("remote online: %v", err)
		return
	}
	remoteBody, _ := io.ReadAll(io.LimitReader(remote.Body, 512))
	remote.Body.Close()
	if remote.StatusCode < 200 || remote.StatusCode >= 300 {
		log.Printf("remote online: HTTP %d body=%q", remote.StatusCode, string(remoteBody))
		return
	}
	log.Printf("online enviado: %d usuario(s) al nodo %s", len(users), payload.IPv4)
}
