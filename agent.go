package relintio

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Config struct {
	LicenseKey   string
	ApiUrl       string
	Domain       string
	SyncInterval time.Duration
}

type Rule struct {
	ID        string `json:"id"`
	Type      string `json:"type"`      // "ip", "user_agent", "path", "header"
	Pattern   string `json:"pattern"`   // Value to match
	Action    string `json:"action"`    // "block", "challenge", "allow"
	Condition string `json:"condition"` // "equals", "contains", "regex"
	Score     int    `json:"score"`
}

type RuleResponse struct {
	Rules []Rule `json:"rules"`
}

type Agent struct {
	config      Config
	rules       []Rule
	mu          sync.RWMutex
	client      *http.Client
	stopCh      chan struct{}
	telemetryCh chan telemetryEvent
	startOnce   sync.Once
	stopOnce    sync.Once
}

const agentVersion = "0.1.0"

type telemetryEvent struct {
	ip        string
	userAgent string
	path      string
	result    ThreatResult
}

func NewAgent(cfg Config) *Agent {
	if cfg.ApiUrl == "" {
		cfg.ApiUrl = "https://relintio.com/api"
	}
	if cfg.SyncInterval == 0 {
		cfg.SyncInterval = 60 * time.Second
	}

	agent := &Agent{
		config:      cfg,
		client:      &http.Client{Timeout: 10 * time.Second},
		stopCh:      make(chan struct{}),
		telemetryCh: make(chan telemetryEvent, 1024),
	}
	go agent.telemetryLoop()

	return agent
}

func (a *Agent) StartSync() {
	a.startOnce.Do(func() {
		go func() {
			// Run initial sync
			a.syncRules()

			ticker := time.NewTicker(a.config.SyncInterval)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					a.syncRules()
				case <-a.stopCh:
					return
				}
			}
		}()
	})
}

func (a *Agent) StopSync() {
	a.stopOnce.Do(func() { close(a.stopCh) })
}

func (a *Agent) syncRules() {
	url := fmt.Sprintf("%s/agent/verify", strings.TrimRight(a.config.ApiUrl, "/"))
	payload := map[string]interface{}{
		"license_key":      a.config.LicenseKey,
		"domain":           a.config.Domain,
		"protocol_version": 1,
		"agent_kind":       "go",
		"agent_version":    agentVersion,
		"capabilities":     []string{"custom_rules", "telemetry"},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024+1))
	if err != nil {
		return
	}
	if len(bodyBytes) > 1024*1024 {
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

	ip := requestIP(r)

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
	event := telemetryEvent{
		ip:        requestIP(r),
		userAgent: r.UserAgent(),
		path:      r.URL.Path,
		result:    result,
	}
	select {
	case a.telemetryCh <- event:
	default:
	}
}

func (a *Agent) telemetryLoop() {
	for {
		select {
		case event := <-a.telemetryCh:
			a.sendTelemetry(event)
		case <-a.stopCh:
			return
		}
	}
}

func (a *Agent) sendTelemetry(event telemetryEvent) {
	url := fmt.Sprintf("%s/agent/log", strings.TrimRight(a.config.ApiUrl, "/"))

	payload := map[string]interface{}{
		"license_key":      a.config.LicenseKey,
		"ip":               event.ip,
		"user_agent":       event.userAgent,
		"path":             event.path,
		"risk_score":       min(max(event.result.Score, 0), 100),
		"action":           strings.ToUpper(event.result.Action),
		"reason_code":      "sdk_rule",
		"protocol_version": 1,
		"agent_kind":       "go",
		"agent_version":    agentVersion,
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

func requestIP(r *http.Request) string {
	ip := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0])
	if ip == "" {
		ip = r.RemoteAddr
	}
	if host, _, err := net.SplitHostPort(ip); err == nil {
		return host
	}
	return strings.Trim(ip, "[]")
}
