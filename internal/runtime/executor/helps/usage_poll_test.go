package helps

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestParseClaudeUsageSignals(t *testing.T) {
	signals, err := ParseClaudeUsageSignals([]byte(`{
		"five_hour": {"utilization": 37.5, "resets_at": "2026-10-22T10:30:00.123456+00:00"},
		"seven_day": {"utilization": 96, "resets_at": "2026-10-25T00:00:00Z"},
		"seven_day_opus": {"utilization": 99, "resets_at": "2026-10-25T00:00:00Z"},
		"extra_usage": {"is_enabled": false}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"Anthropic-Ratelimit-Unified-5h-Utilization": "0.375",
		"Anthropic-Ratelimit-Unified-5h-Reset":       "1792665000",
		"Anthropic-Ratelimit-Unified-7d-Utilization": "0.96",
		"Anthropic-Ratelimit-Unified-7d-Reset":       "1792886400",
	}
	if !reflect.DeepEqual(signals, want) {
		t.Fatalf("signals = %v\nwant     %v", signals, want)
	}
}

func TestParseClaudeUsageSignalsToleratesPartialPayloads(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       map[string]string
		err        string
	}{
		{"weekly window missing", `{"five_hour":{"utilization":10,"resets_at":null},"seven_day":null}`,
			map[string]string{"Anthropic-Ratelimit-Unified-5h-Utilization": "0.1"}, ""},
		{"utilization as numeric string", `{"seven_day":{"utilization":"42"}}`,
			map[string]string{"Anthropic-Ratelimit-Unified-7d-Utilization": "0.42"}, ""},
		{"unix reset", `{"five_hour":{"utilization":1,"resets_at":1792665000}}`,
			map[string]string{"Anthropic-Ratelimit-Unified-5h-Utilization": "0.01", "Anthropic-Ratelimit-Unified-5h-Reset": "1792665000"}, ""},
		{"over-full window", `{"five_hour":{"utilization":104}}`,
			map[string]string{"Anthropic-Ratelimit-Unified-5h-Utilization": "1.04"}, ""},
		{"negative and non-numeric windows are skipped", `{"five_hour":{"utilization":-1},"seven_day":{"utilization":"soon"}}`, nil, "no usage windows in response"},
		{"no windows", `{"extra_usage":{}}`, nil, "no usage windows in response"},
		{"not json", `<html>blocked</html>`, nil, "unparseable response"},
		{"empty", ``, nil, "unparseable response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseClaudeUsageSignals([]byte(tc.body))
			if tc.err != "" {
				if err == nil || err.Error() != tc.err {
					t.Fatalf("error = %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

func TestParseCodexUsageSignals(t *testing.T) {
	signals, err := ParseCodexUsageSignals([]byte(`{
		"plan_type": "plus",
		"rate_limit": {
			"allowed": true,
			"limit_reached": false,
			"primary_window": {"used_percent": 12.5, "limit_window_seconds": 18000, "reset_after_seconds": 3600, "reset_at": 1792665000},
			"secondary_window": {"used_percent": 61, "limit_window_seconds": 604800, "reset_after_seconds": 400000, "reset_at": 1792886400}
		},
		"credits": {"has_credits": true, "unlimited": false, "balance": "12.50"},
		"additional_rate_limits": [{"limit_name": "GPT-5.3-Codex-Spark", "rate_limit": {"primary_window": {"used_percent": 99}}}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"X-Codex-Primary-Used-Percent":          "12.5",
		"X-Codex-Primary-Window-Minutes":        "300",
		"X-Codex-Primary-Reset-At":              "1792665000",
		"X-Codex-Primary-Reset-After-Seconds":   "3600",
		"X-Codex-Secondary-Used-Percent":        "61",
		"X-Codex-Secondary-Window-Minutes":      "10080",
		"X-Codex-Secondary-Reset-At":            "1792886400",
		"X-Codex-Secondary-Reset-After-Seconds": "400000",
		"X-Codex-Allowed":                       "true",
		"X-Codex-Limit-Reached":                 "false",
		"X-Codex-Plan-Type":                     "plus",
		"X-Codex-Credits-Has-Credits":           "true",
		"X-Codex-Credits-Unlimited":             "false",
		"X-Codex-Credits-Balance":               "12.50",
	}
	if !reflect.DeepEqual(signals, want) {
		t.Fatalf("signals = %v\nwant     %v", signals, want)
	}
}

func TestParseCodexUsageSignalsCurrentWeeklyOnlyPlan(t *testing.T) {
	// The dashboard's fixture for a current plan: one weekly window in the
	// primary position and no secondary window.
	signals, err := ParseCodexUsageSignals([]byte(`{
		"plan_type": "pro",
		"rate_limit": {"allowed": true, "limit_reached": false,
			"primary_window": {"used_percent": 1, "limit_window_seconds": 604800, "reset_after_seconds": 601888, "reset_at": 1785902974},
			"secondary_window": null},
		"code_review_rate_limit": null,
		"additional_rate_limits": []
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if signals["X-Codex-Primary-Used-Percent"] != "1" || signals["X-Codex-Primary-Window-Minutes"] != "10080" {
		t.Fatalf("weekly primary window lost its length: %v", signals)
	}
	for key := range signals {
		if strings.HasPrefix(key, "X-Codex-Secondary-") {
			t.Fatalf("absent secondary window produced %s", key)
		}
	}
}

func TestParseCodexUsageSignalsEdgeCases(t *testing.T) {
	// Camel-case keys, and a reset in milliseconds.
	signals, err := ParseCodexUsageSignals([]byte(`{"rateLimit":{"primaryWindow":{"usedPercent":"20","resetAt":1792665000000}}}`))
	if err != nil || signals["X-Codex-Primary-Used-Percent"] != "20" || signals["X-Codex-Primary-Reset-At"] != "1792665000" {
		t.Fatalf("camel case / ms reset: %v %v", signals, err)
	}
	// An exhausted limit with no figure reads as full, like the dashboard.
	signals, err = ParseCodexUsageSignals([]byte(`{"rate_limit":{"allowed":false,"limit_reached":true,"primary_window":{"reset_after_seconds":120}}}`))
	if err != nil || signals["X-Codex-Primary-Used-Percent"] != "100" || signals["X-Codex-Limit-Reached"] != "true" || signals["X-Codex-Allowed"] != "false" {
		t.Fatalf("exhausted limit: %v %v", signals, err)
	}
	// A missing figure on a healthy limit is not data.
	if _, err = ParseCodexUsageSignals([]byte(`{"rate_limit":{"allowed":true,"primary_window":{"reset_after_seconds":120}}}`)); err == nil || err.Error() != "no usage windows in response" {
		t.Fatalf("figureless window accepted: %v", err)
	}
	for _, body := range []string{`{}`, `{"rate_limit":null}`, `{"rate_limit":{"primary_window":null,"secondary_window":null}}`, `{"rate_limit":{"primary_window":{"used_percent":-3}}}`} {
		if _, err = ParseCodexUsageSignals([]byte(body)); err == nil || err.Error() != "no usage windows in response" {
			t.Fatalf("%s: %v", body, err)
		}
	}
	if _, err = ParseCodexUsageSignals([]byte(`not json`)); err == nil || err.Error() != "unparseable response" {
		t.Fatalf("garbage: %v", err)
	}
	// Control characters in upstream text never reach the signals.
	signals, err = ParseCodexUsageSignals([]byte(`{"plan_type":"plus\nforged: 1","rate_limit":{"primary_window":{"used_percent":5}}}`))
	if err != nil || signals["X-Codex-Plan-Type"] != "" {
		t.Fatalf("multi-line plan type kept: %v %v", signals, err)
	}
}

type recordedRequest struct {
	path   string
	header http.Header
}

func usageServer(t *testing.T, status int, body string, seen *atomic.Pointer[recordedRequest]) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Store(&recordedRequest{path: r.Method + " " + r.URL.Path, header: r.Header.Clone()})
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server
}

func TestClaudeProbeRequestShapeAndMapping(t *testing.T) {
	var seen atomic.Pointer[recordedRequest]
	server := usageServer(t, 200, `{"five_hour":{"utilization":3,"resets_at":"2026-10-22T10:30:00Z"},"seven_day":{"utilization":50}}`, &seen)
	signals, err := UsageProbes{ClaudeURL: server.URL + "/api/oauth/usage"}.Claude(context.Background(), &cliproxyauth.Auth{ID: "c", Provider: "claude"}, "synthetic-claude-token")
	if err != nil {
		t.Fatal(err)
	}
	req := seen.Load()
	if req.path != "GET /api/oauth/usage" || req.header.Get("Authorization") != "Bearer synthetic-claude-token" ||
		req.header.Get("anthropic-beta") != "oauth-2025-04-20" || req.header.Get("User-Agent") != "claude-cli/2.1.280 (external, cli)" {
		t.Fatalf("request: %s %v", req.path, req.header)
	}
	if signals["Anthropic-Ratelimit-Unified-5h-Utilization"] != "0.03" || signals["Anthropic-Ratelimit-Unified-5h-Reset"] != "1792665000" || signals["Anthropic-Ratelimit-Unified-7d-Utilization"] != "0.5" {
		t.Fatalf("signals: %v", signals)
	}
}

func TestClaudeProbeUsesConfiguredUserAgent(t *testing.T) {
	var seen atomic.Pointer[recordedRequest]
	server := usageServer(t, 200, `{"five_hour":{"utilization":3}}`, &seen)
	cfg := &config.Config{}
	cfg.ClaudeHeaderDefaults.UserAgent = "claude-cli/9.9.9 (external, cli)"
	probes := UsageProbes{ClaudeURL: server.URL, Config: func() *config.Config { return cfg }}
	if _, err := probes.Claude(context.Background(), &cliproxyauth.Auth{ID: "c"}, "t"); err != nil {
		t.Fatal(err)
	}
	if got := seen.Load().header.Get("User-Agent"); got != "claude-cli/9.9.9 (external, cli)" {
		t.Fatalf("user agent = %q", got)
	}
}

func TestCodexProbeRequestShapeAndMapping(t *testing.T) {
	var seen atomic.Pointer[recordedRequest]
	server := usageServer(t, 200, `{"plan_type":"plus","rate_limit":{"primary_window":{"used_percent":4,"limit_window_seconds":18000,"reset_at":1792665000}}}`, &seen)
	auth := &cliproxyauth.Auth{ID: "x", Provider: "codex", Metadata: map[string]any{"account_id": " acct-synthetic "}}
	signals, err := UsageProbes{CodexURL: server.URL + "/backend-api/wham/usage"}.Codex(context.Background(), auth, "synthetic-codex-token")
	if err != nil {
		t.Fatal(err)
	}
	req := seen.Load()
	if req.path != "GET /backend-api/wham/usage" || req.header.Get("Authorization") != "Bearer synthetic-codex-token" ||
		req.header.Get("Chatgpt-Account-Id") != "acct-synthetic" || !strings.HasPrefix(req.header.Get("User-Agent"), "codex-tui/") {
		t.Fatalf("request: %s %v", req.path, req.header)
	}
	if signals["X-Codex-Primary-Used-Percent"] != "4" || signals["X-Codex-Plan-Type"] != "plus" {
		t.Fatalf("signals: %v", signals)
	}

	// No account ID in the metadata: the header is omitted, as the dashboard does.
	seen.Store(nil)
	if _, err = (UsageProbes{CodexURL: server.URL}).Codex(context.Background(), &cliproxyauth.Auth{ID: "y"}, "t"); err != nil {
		t.Fatal(err)
	}
	if _, present := seen.Load().header["Chatgpt-Account-Id"]; present {
		t.Fatal("account header sent without an account ID")
	}
	// The alternate metadata spellings are honoured.
	if got := codexUsageAccountID(&cliproxyauth.Auth{Metadata: map[string]any{"chatgpt_account_id": "alt"}}); got != "alt" {
		t.Fatalf("alternate account ID = %q", got)
	}
}

func TestProbeErrorsAreClassifiedWithoutSecrets(t *testing.T) {
	const token = "synthetic-secret-token-value"
	for _, tc := range []struct {
		status int
		body   string
		want   string
	}{
		{401, `{"error":"invalid token ` + token + `"}`, "HTTP 401"},
		{403, `{"error":"forbidden"}`, "HTTP 403"},
		{429, `rate limited`, "HTTP 429"},
		{500, ``, "HTTP 500"},
		{302, ``, "HTTP 302"},
		{200, `<html>` + token + `</html>`, "unparseable response"},
		{200, `{"five_hour":null}`, "no usage windows in response"},
	} {
		var seen atomic.Pointer[recordedRequest]
		server := usageServer(t, tc.status, tc.body, &seen)
		_, err := UsageProbes{ClaudeURL: server.URL}.Claude(context.Background(), &cliproxyauth.Auth{ID: "c"}, token)
		if err == nil || err.Error() != tc.want || strings.Contains(err.Error(), token) {
			t.Fatalf("status %d: error = %v, want %q", tc.status, err, tc.want)
		}
	}
}

func TestProbeDoesNotFollowRedirectsWithTheBearerToken(t *testing.T) {
	var elsewhere atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) }))
	t.Cleanup(target.Close)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	t.Cleanup(redirector.Close)
	if _, err := (UsageProbes{CodexURL: redirector.URL}).Codex(context.Background(), &cliproxyauth.Auth{ID: "x"}, "token"); err == nil || err.Error() != "HTTP 302" {
		t.Fatalf("redirect: %v", err)
	}
	if elsewhere.Load() != 0 {
		t.Fatal("redirect target was contacted")
	}
}

func TestProbeTransportFailureAndCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close()
	if _, err := (UsageProbes{ClaudeURL: url}).Claude(context.Background(), &cliproxyauth.Auth{ID: "c"}, "token"); err == nil || err.Error() != "request failed" {
		t.Fatalf("closed server: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (UsageProbes{ClaudeURL: url}).Claude(ctx, &cliproxyauth.Auth{ID: "c"}, "token"); err == nil || ctx.Err() == nil || err.Error() != context.Canceled.Error() {
		t.Fatalf("canceled context must surface as cancellation, got %v", err)
	}
}

func TestProbeRejectsOversizedResponses(t *testing.T) {
	var seen atomic.Pointer[recordedRequest]
	server := usageServer(t, 200, `{"five_hour":{"utilization":1},"pad":"`+strings.Repeat("x", maxUsageResponseBytes)+`"}`, &seen)
	if _, err := (UsageProbes{ClaudeURL: server.URL}).Claude(context.Background(), &cliproxyauth.Auth{ID: "c"}, "t"); err == nil || err.Error() != "response too large" {
		t.Fatalf("oversized response: %v", err)
	}
}
