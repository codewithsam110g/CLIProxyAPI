package helps

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

// Provider usage endpoints the quota dashboard already queries. The session
// router polls the same ones, with the same request shape.
const (
	ClaudeUsageURL = "https://api.anthropic.com/api/oauth/usage"
	CodexUsageURL  = "https://chatgpt.com/backend-api/wham/usage"

	defaultCodexUsageUserAgent = "codex-tui/0.154.0 (Mac OS 26.5.2; arm64) iTerm.app/3.6.11 (codex-tui; 0.154.0)"
	maxUsageResponseBytes      = 1 << 20
)

// UsageProbes fetches provider usage and maps it to the quota signals the router
// reads from response headers. Errors are short classifications without tokens,
// headers or response bodies: they are stored and served by the management API.
type UsageProbes struct {
	// Config returns the live configuration for proxy settings and header
	// defaults. It may be nil.
	Config func() *config.Config
	// ClaudeURL and CodexURL override the endpoints; empty selects production.
	ClaudeURL string
	CodexURL  string
}

// Claude polls the Claude OAuth usage endpoint for one credential.
func (p UsageProbes) Claude(ctx context.Context, auth *cliproxyauth.Auth, accessToken string) (map[string]string, error) {
	userAgent := defaultClaudeFingerprintUserAgent
	if cfg := p.config(); cfg != nil && strings.TrimSpace(cfg.ClaudeHeaderDefaults.UserAgent) != "" {
		userAgent = strings.TrimSpace(cfg.ClaudeHeaderDefaults.UserAgent)
	}
	body, err := p.fetch(ctx, auth, firstNonEmpty(p.ClaudeURL, ClaudeUsageURL), map[string]string{
		"Authorization":  "Bearer " + accessToken,
		"anthropic-beta": "oauth-2025-04-20",
		"User-Agent":     userAgent,
		"Accept":         "application/json",
	})
	if err != nil {
		return nil, err
	}
	return ParseClaudeUsageSignals(body)
}

// Codex polls the ChatGPT backend usage endpoint for one credential.
func (p UsageProbes) Codex(ctx context.Context, auth *cliproxyauth.Auth, accessToken string) (map[string]string, error) {
	userAgent := defaultCodexUsageUserAgent
	if cfg := p.config(); cfg != nil && strings.TrimSpace(cfg.CodexHeaderDefaults.UserAgent) != "" {
		userAgent = strings.TrimSpace(cfg.CodexHeaderDefaults.UserAgent)
	}
	header := map[string]string{
		"Authorization": "Bearer " + accessToken,
		"Accept":        "application/json",
		"User-Agent":    userAgent,
	}
	if accountID := codexUsageAccountID(auth); accountID != "" {
		header["Chatgpt-Account-Id"] = accountID
	}
	body, err := p.fetch(ctx, auth, firstNonEmpty(p.CodexURL, CodexUsageURL), header)
	if err != nil {
		return nil, err
	}
	return ParseCodexUsageSignals(body)
}

func (p UsageProbes) config() *config.Config {
	if p.Config == nil {
		return nil
	}
	return p.Config()
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func codexUsageAccountID(auth *cliproxyauth.Auth) string {
	if auth == nil {
		return ""
	}
	for _, key := range []string{"account_id", "chatgpt_account_id", "chatgptAccountId"} {
		if v, ok := auth.Metadata[key].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// fetch performs one GET. It sets no timeout: after the connection is
// established the project forbids one, and the caller's context ends the call.
// Redirects are not followed so the bearer token cannot be forwarded elsewhere.
func (p UsageProbes) fetch(ctx context.Context, auth *cliproxyauth.Auth, url string, header map[string]string) ([]byte, error) {
	client := NewProxyAwareHTTPClient(ctx, p.config(), auth, 0)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.New("invalid usage request")
	}
	for name, value := range header {
		req.Header.Set(name, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, errors.New("request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxUsageResponseBytes+1))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, errors.New("response read failed")
	}
	if len(body) > maxUsageResponseBytes {
		return nil, errors.New("response too large")
	}
	return body, nil
}

var errNoUsageWindows = errors.New("no usage windows in response")

// ParseClaudeUsageSignals maps a Claude usage payload to router signals. The
// five_hour and seven_day windows carry utilization as a percent; the router's
// header spelling is a 0..1 fraction, and the reset is Unix seconds.
func ParseClaudeUsageSignals(body []byte) (map[string]string, error) {
	if !gjson.ValidBytes(body) {
		return nil, errors.New("unparseable response")
	}
	root := gjson.ParseBytes(body)
	signals := make(map[string]string)
	for _, window := range []struct{ key, prefix string }{
		{"five_hour", "Anthropic-Ratelimit-Unified-5h-"},
		{"seven_day", "Anthropic-Ratelimit-Unified-7d-"},
	} {
		node := root.Get(window.key)
		if !node.IsObject() {
			continue
		}
		utilization, ok := usageNumber(node.Get("utilization"))
		if !ok || utilization < 0 {
			continue
		}
		signals[window.prefix+"Utilization"] = formatUsageNumber(utilization / 100)
		if reset, ok := usageResetUnix(node.Get("resets_at")); ok {
			signals[window.prefix+"Reset"] = strconv.FormatInt(reset, 10)
		}
	}
	if len(signals) == 0 {
		return nil, errNoUsageWindows
	}
	return signals, nil
}

// ParseCodexUsageSignals maps a Codex usage payload to router signals, using the
// positional primary/secondary names the response headers use. The window length
// is passed along because a plan may report only a weekly window as "primary".
func ParseCodexUsageSignals(body []byte) (map[string]string, error) {
	if !gjson.ValidBytes(body) {
		return nil, errors.New("unparseable response")
	}
	root := gjson.ParseBytes(body)
	rate := firstUsageResult(root, "rate_limit", "rateLimit")
	if !rate.IsObject() {
		return nil, errNoUsageWindows
	}
	allowed, hasAllowed := usageBool(rate.Get("allowed"))
	limitReached, hasLimitReached := usageBool(firstUsageResult(rate, "limit_reached", "limitReached"))
	exhausted := (hasLimitReached && limitReached) || (hasAllowed && !allowed)

	signals := make(map[string]string)
	windows := 0
	for _, window := range []struct {
		name string
		keys []string
	}{
		{"Primary", []string{"primary_window", "primaryWindow"}},
		{"Secondary", []string{"secondary_window", "secondaryWindow"}},
	} {
		node := firstUsageResult(rate, window.keys...)
		if !node.IsObject() {
			continue
		}
		prefix := "X-Codex-" + window.name + "-"
		resetAt, hasResetAt := usageUnixSeconds(firstUsageResult(node, "reset_at", "resetAt"))
		resetAfter, hasResetAfter := usageNumber(firstUsageResult(node, "reset_after_seconds", "resetAfterSeconds"))
		hasResetAfter = hasResetAfter && resetAfter >= 0
		used, ok := usageNumber(firstUsageResult(node, "used_percent", "usedPercent"))
		if !ok && exhausted && (hasResetAt || hasResetAfter) {
			// The dashboard reads a window of an exhausted limit with no figure as full.
			used, ok = 100, true
		}
		if !ok || used < 0 {
			continue
		}
		signals[prefix+"Used-Percent"] = formatUsageNumber(used)
		if seconds, ok := usageNumber(firstUsageResult(node, "limit_window_seconds", "limitWindowSeconds")); ok && seconds > 0 {
			signals[prefix+"Window-Minutes"] = strconv.FormatInt(int64(math.Round(seconds/60)), 10)
		}
		if hasResetAt {
			signals[prefix+"Reset-At"] = strconv.FormatInt(resetAt, 10)
		}
		if hasResetAfter {
			signals[prefix+"Reset-After-Seconds"] = strconv.FormatInt(int64(math.Round(resetAfter)), 10)
		}
		windows++
	}
	if windows == 0 {
		return nil, errNoUsageWindows
	}
	if hasAllowed {
		signals["X-Codex-Allowed"] = strconv.FormatBool(allowed)
	}
	if hasLimitReached {
		signals["X-Codex-Limit-Reached"] = strconv.FormatBool(limitReached)
	}
	if plan := usageScalar(firstUsageResult(root, "plan_type", "planType")); validUsageText(plan) {
		signals["X-Codex-Plan-Type"] = plan
	}
	if credits := root.Get("credits"); credits.IsObject() {
		for _, field := range []struct{ header, key, alt string }{
			{"X-Codex-Credits-Has-Credits", "has_credits", "hasCredits"},
			{"X-Codex-Credits-Unlimited", "unlimited", ""},
			{"X-Codex-Credits-Balance", "balance", ""},
		} {
			if value := usageScalar(firstUsageResult(credits, field.key, field.alt)); validUsageText(value) {
				signals[field.header] = value
			}
		}
	}
	return signals, nil
}

func firstUsageResult(node gjson.Result, keys ...string) gjson.Result {
	for _, key := range keys {
		if key == "" {
			continue
		}
		if value := node.Get(key); value.Exists() && value.Type != gjson.Null {
			return value
		}
	}
	return gjson.Result{}
}

// usageNumber reads a finite JSON number or numeric string.
func usageNumber(value gjson.Result) (float64, bool) {
	var number float64
	switch value.Type {
	case gjson.Number:
		number = value.Float()
	case gjson.String:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(value.String()), 64)
		if err != nil {
			return 0, false
		}
		number = parsed
	default:
		return 0, false
	}
	if math.IsNaN(number) || math.IsInf(number, 0) {
		return 0, false
	}
	return number, true
}

func usageBool(value gjson.Result) (bool, bool) {
	switch value.Type {
	case gjson.True:
		return true, true
	case gjson.False:
		return false, true
	}
	return false, false
}

func usageScalar(value gjson.Result) string {
	switch value.Type {
	case gjson.String:
		return strings.TrimSpace(value.String())
	case gjson.Number, gjson.True, gjson.False:
		return strings.TrimSpace(value.Raw)
	}
	return ""
}

func validUsageText(value string) bool {
	return value != "" && len(value) <= 256 && !strings.ContainsAny(value, "\r\n")
}

// usageUnixSeconds accepts Unix seconds, or milliseconds by magnitude as the
// dashboard does, and returns seconds.
func usageUnixSeconds(value gjson.Result) (int64, bool) {
	number, ok := usageNumber(value)
	if !ok || number <= 0 {
		return 0, false
	}
	if number >= 1e11 {
		number /= 1000
	}
	return int64(number), true
}

// usageResetUnix reads an ISO-8601 timestamp or a Unix instant as Unix seconds.
func usageResetUnix(value gjson.Result) (int64, bool) {
	if value.Type == gjson.String {
		if parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(value.String())); err == nil && parsed.Unix() > 0 {
			return parsed.Unix(), true
		}
	}
	return usageUnixSeconds(value)
}

func formatUsageNumber(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}
