package relintio

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Config struct {
	LicenseKey   string
	ApiUrl       string
	SyncInterval time.Duration
}

type Rule struct {
	ID        string   `json:"id"`
	Type      string   `json:"type"`      // "ip", "user_agent", "path", "header"
	Pattern   string   `json:"pattern"`   // Value to match
	Action    string   `json:"action"`    // "block", "challenge", "allow"
	Condition string   `json:"condition"` // "equals", "contains", "regex"
	Score     int      `json:"score"`
}

type RuleResponse struct {
	Rules []Rule `json:"rules"`
}

type Agent struct {
	config Config
	rules  []Rule
	mu     sync.RWMutex
	client *http.Client
}

func NewAgent(cfg Config) *Agent {
	if cfg.ApiUrl == "" {
		cfg.ApiUrl = "https://api.relintio.com/api"
	}
	if cfg.SyncInterval == 0 {
		cfg.SyncInterval = 60 * time.Second
	}

	agent := &Agent{
		config: cfg,
		client: &http.Client{Timeout: 10 * time.Second},
	}

	return agent
}

func (a *Agent) StartSync() {
	go func() {
		// Run initial sync
		a.syncRules()

		ticker := time.NewTicker(a.config.SyncInterval)
		defer ticker.Stop()

		for range ticker.C {
			a.syncRules()
		}
	}()
}

func (a *Agent) syncRules() {
	url := fmt.Sprintf("%s/rules/sync", strings.TrimRight(a.config.ApiUrl, "/"))
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.config.LicenseKey))
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	var res RuleResponse
	if err := json.Unmarshal(bodyBytes, &res); err != nil {
		return
	}

	a.mu.Lock()
	a.rules = res.Rules
	a.mu.Unlock()
}

type ThreatResult struct {
	Score  int
	Action string
}

func (a *Agent) CheckRequest(r *http.Request) ThreatResult {
	a.mu.RLock()
	defer a.mu.RUnlock()

	ip := r.RemoteAddr
	if prior := r.Header.Get("X-Forwarded-For"); prior != "" {
		ip = strings.Split(prior, ",")[0]
	}
	if colon := strings.LastIndex(ip, ":"); colon != -1 {
		ip = ip[:colon]
	}

	userAgent := r.UserAgent()
	path := r.URL.Path

	score := 0
	action := "allow"

	for _, rule := range a.rules {
		matched := false
		switch rule.Type {
		case "ip":
			matched = a.matchValue(ip, rule.Pattern, rule.Condition)
		case "user_agent":
			matched = a.matchValue(userAgent, rule.Pattern, rule.Condition)
		case "path":
			matched = a.matchValue(path, rule.Pattern, rule.Condition)
		}

		if matched {
			score += rule.Score
			if rule.Action == "block" {
				action = "block"
			} else if rule.Action == "challenge" && action != "block" {
				action = "challenge"
			}
		}
	}

	if score >= 100 {
		action = "block"
	} else if score >= 50 && action != "block" {
		action = "challenge"
	}

	return ThreatResult{
		Score:  score,
		Action: action,
	}
}

func (a *Agent) matchValue(val, pattern, condition string) bool {
	switch condition {
	case "equals":
		return val == pattern
	case "contains":
		return strings.Contains(strings.ToLower(val), strings.ToLower(pattern))
	default:
		return strings.Contains(strings.ToLower(val), strings.ToLower(pattern))
	}
}

func (a *Agent) SendTelemetry(r *http.Request, result ThreatResult) {
	go func() {
		url := fmt.Sprintf("%s/telemetry/log", strings.TrimRight(a.config.ApiUrl, "/"))
		
		ip := r.RemoteAddr
		if prior := r.Header.Get("X-Forwarded-For"); prior != "" {
			ip = strings.Split(prior, ",")[0]
		}
		if colon := strings.LastIndex(ip, ":"); colon != -1 {
			ip = ip[:colon]
		}

		payload := map[string]interface{}{
			"ip":          ip,
			"user_agent":  r.UserAgent(),
			"path":        r.URL.Path,
			"score":       result.Score,
			"action":      result.Action,
			"timestamp":   time.Now().Unix(),
		}

		jsonBytes, err := json.Marshal(payload)
		if err != nil {
			return
		}

		req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBytes))
		if err != nil {
			return
		}

		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.config.LicenseKey))
		req.Header.Set("Content-Type", "application/json")

		resp, err := a.client.Do(req)
		if err != nil {
			return
		}
		resp.Body.Close()
	}()
}
