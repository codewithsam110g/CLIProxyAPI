package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	executor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestManagementRoutingSessionControls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("port: 8317\nremote-management: {secret-key: test-password}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AuthDir = t.TempDir()
	selector := coreauth.NewSessionBalancedSelector(filepath.Join(cfg.AuthDir, "state"), time.Hour)
	defer selector.Stop()
	manager := coreauth.NewManager(nil, selector, nil)
	pool := []*coreauth.Auth{{ID: "route-a", Provider: "codex"}, {ID: "route-b", Provider: "codex"}}
	for _, a := range pool {
		if _, err := manager.Register(context.Background(), a); err != nil {
			t.Fatal(err)
		}
		registry.GetGlobalRegistry().RegisterClient(a.ID, "codex", []*registry.ModelInfo{{ID: "route-model"}})
		defer registry.GetGlobalRegistry().UnregisterClient(a.ID)
	}
	if _, err := selector.Pick(context.Background(), "codex", "route-model", executor.Options{Headers: http.Header{"X-Session-Id": {"session-one"}}, Metadata: map[string]any{executor.CallerScopeMetadataKey: "synthetic-caller"}}, pool); err != nil {
		t.Fatal(err)
	}
	h := management.NewHandler(cfg, path, manager)
	h.SetLocalPassword("test-password")
	s := &Server{cfg: cfg, engine: gin.New(), mgmt: h}
	s.managementRoutesEnabled.Store(true)
	s.registerManagementRoutes()
	call := func(method, url, body string, authorized bool, want int) string {
		t.Helper()
		r := httptest.NewRequest(method, url, strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set("Content-Type", "application/json")
		if authorized {
			r.Header.Set("Authorization", "Bearer test-password")
		}
		w := httptest.NewRecorder()
		s.engine.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %s status=%d body=%s", method, url, w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	for _, route := range []struct{ method, url, body string }{{"GET", "/v8/management/routing/sessions", ""}, {"POST", "/v8/management/routing/sessions/move", `{}`}, {"POST", "/v8/management/routing/accounts/drain", `{}`}} {
		call(route.method, route.url, route.body, false, 401)
	}
	var snapshot coreauth.BalancedRoutingSnapshot
	if err := json.Unmarshal([]byte(call("GET", "/v8/management/routing/sessions", "", true, 200)), &snapshot); err != nil {
		t.Fatal(err)
	}
	if !snapshot.Enabled || len(snapshot.Sessions) != 1 || len(snapshot.Accounts) != 2 {
		t.Fatalf("snapshot: %+v", snapshot)
	}
	row := snapshot.Sessions[0]
	call("POST", "/v8/management/routing/accounts/drain", `{"auth_id":"route-b"}`, true, 400)
	call("POST", "/v8/management/routing/accounts/drain", `{"auth_id":"missing","draining":true}`, true, 409)
	call("POST", "/v8/management/routing/accounts/drain", `{"auth_id":"route-b","draining":true}`, true, 200)
	move := func(gen uint64) string {
		b, _ := json.Marshal(map[string]any{"id": row.ID, "auth_id": "route-b", "expected_generation": gen})
		return string(b)
	}
	call("POST", "/v8/management/routing/sessions/move", move(row.Generation), true, 409)
	call("POST", "/v8/management/routing/accounts/drain", `{"auth_id":"route-b","draining":false}`, true, 200)
	call("POST", "/v8/management/routing/sessions/move", move(row.Generation+1), true, 409)
	call("POST", "/v8/management/routing/sessions/move", move(row.Generation), true, 200)
	pending := selector.Snapshot().Sessions[0]
	if pending.AuthID != row.AuthID || pending.PendingAuthID != "route-b" {
		t.Fatal("move was not deferred to a safe request")
	}
	manager.SetSelector(&coreauth.RoundRobinSelector{})
	call("POST", "/v8/management/routing/accounts/drain", `{"auth_id":"route-b","draining":true}`, true, 409)
	if body := call("GET", "/v8/management/routing/sessions", "", true, 200); !strings.Contains(body, `"enabled":false`) {
		t.Fatal(body)
	}
}

// quotaRefreshFixture serves the management routes over a session-balanced
// manager whose poller uses a counting fake probe instead of the network.
type quotaRefreshFixture struct {
	t        *testing.T
	manager  *coreauth.Manager
	selector *coreauth.SessionBalancedSelector
	probes   atomic.Int32
	failure  atomic.Value // string
	engine   *gin.Engine
}

func newQuotaRefreshFixture(t *testing.T) *quotaRefreshFixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("port: 8317\nremote-management: {secret-key: test-password}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AuthDir = t.TempDir()
	f := &quotaRefreshFixture{t: t}
	f.selector = coreauth.NewSessionBalancedSelector("", time.Hour)
	t.Cleanup(f.selector.Stop)
	f.manager = coreauth.NewManager(nil, f.selector, nil)
	expires := time.Now().Add(time.Hour).Format(time.RFC3339)
	for _, a := range []*coreauth.Auth{
		{ID: "route-a", Provider: "codex", Metadata: map[string]any{"access_token": "synthetic-a", "expired": expires}},
		{ID: "route-b", Provider: "codex", Metadata: map[string]any{"access_token": "synthetic-b", "expired": expires}},
		{ID: "route-key", Provider: "claude", Attributes: map[string]string{"api_key": "synthetic-api-key"}},
	} {
		if _, err := f.manager.Register(context.Background(), a); err != nil {
			t.Fatal(err)
		}
	}
	probe := func(_ context.Context, a *coreauth.Auth, _ string) (map[string]string, error) {
		f.probes.Add(1)
		if msg, _ := f.failure.Load().(string); msg != "" {
			return nil, errors.New(msg)
		}
		if a.ID == "route-a" {
			return map[string]string{"X-Codex-Primary-Used-Percent": "97", "X-Codex-Secondary-Used-Percent": "20"}, nil
		}
		return map[string]string{"X-Codex-Primary-Used-Percent": "10", "X-Codex-Secondary-Used-Percent": "10"}, nil
	}
	poller := coreauth.NewQuotaPoller(f.manager, map[string]coreauth.QuotaProbe{"codex": probe, "claude": probe})
	f.manager.SetQuotaPoller(poller)
	t.Cleanup(poller.Stop)
	h := management.NewHandler(cfg, path, f.manager)
	h.SetLocalPassword("test-password")
	s := &Server{cfg: cfg, engine: gin.New(), mgmt: h}
	s.managementRoutesEnabled.Store(true)
	s.registerManagementRoutes()
	f.engine = s.engine
	return f
}

func (f *quotaRefreshFixture) call(method, url, body string, authorized bool, want int) string {
	f.t.Helper()
	r := httptest.NewRequest(method, url, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:1234"
	if authorized {
		r.Header.Set("Authorization", "Bearer test-password")
	}
	w := httptest.NewRecorder()
	f.engine.ServeHTTP(w, r)
	if w.Code != want {
		f.t.Fatalf("%s %s status=%d want=%d body=%s", method, url, w.Code, want, w.Body.String())
	}
	return w.Body.String()
}

type refreshResponse struct {
	Status           string           `json:"status"`
	CoalescedAuthIDs []string         `json:"coalesced_auth_ids"`
	Accounts         []map[string]any `json:"accounts"`
}

func decodeRefresh(t *testing.T, body string) refreshResponse {
	t.Helper()
	var out refreshResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	return out
}

func TestManagementRoutingRefreshQuota(t *testing.T) {
	const url = "/v8/management/routing/accounts/refresh-quota"
	f := newQuotaRefreshFixture(t)
	f.call("POST", url, `{}`, false, 401)
	if f.probes.Load() != 0 {
		t.Fatal("unauthenticated request polled a provider")
	}

	// Happy path for one account: it is polled, the entry is updated, and the stop applies.
	one := decodeRefresh(t, f.call("POST", url, `{"auth_id":"route-a"}`, true, 200))
	if one.Status != "ok" || len(one.CoalescedAuthIDs) != 0 || len(one.Accounts) != 1 || f.probes.Load() != 1 {
		t.Fatalf("single refresh: %+v probes=%d", one, f.probes.Load())
	}
	account := one.Accounts[0]
	if account["id"] != "route-a" || account["quota_stopped"] != true || account["quota_stop_reason"] != "5-hour window at 3% remaining (reserve 5%)" || account["last_poll_error"] != "" || account["last_poll_at"] == "" {
		t.Fatalf("account entry: %v", account)
	}
	windows, _ := account["windows"].([]any)
	if len(windows) != 2 || windows[0].(map[string]any)["kind"] != "short" || windows[0].(map[string]any)["remaining_percent"] != 3.0 || windows[0].(map[string]any)["stopped"] != true {
		t.Fatalf("windows: %v", account["windows"])
	}

	// A second click moments later is coalesced: no provider call, same entry shape.
	again := decodeRefresh(t, f.call("POST", url, `{"auth_id":"route-a"}`, true, 200))
	if !reflect.DeepEqual(again.CoalescedAuthIDs, []string{"route-a"}) || f.probes.Load() != 1 || len(again.Accounts) != 1 {
		t.Fatalf("repeat click: %+v probes=%d", again, f.probes.Load())
	}

	// {} and an empty body refresh every pollable account (route-a is coalesced, route-b polls).
	all := decodeRefresh(t, f.call("POST", url, `{}`, true, 200))
	if len(all.Accounts) != 2 || all.Accounts[0]["id"] != "route-a" || all.Accounts[1]["id"] != "route-b" || !reflect.DeepEqual(all.CoalescedAuthIDs, []string{"route-a"}) || f.probes.Load() != 2 {
		t.Fatalf("refresh all: %+v probes=%d", all, f.probes.Load())
	}
	empty := decodeRefresh(t, f.call("POST", url, ``, true, 200))
	if len(empty.Accounts) != 2 || len(empty.CoalescedAuthIDs) != 2 || f.probes.Load() != 2 {
		t.Fatalf("empty body: %+v probes=%d", empty, f.probes.Load())
	}

	// Rejections: unknown account, an account that cannot be polled, malformed bodies.
	f.call("POST", url, `{"auth_id":"missing"}`, true, 404)
	f.call("POST", url, `{"auth_id":"route-key"}`, true, 400)
	f.call("POST", url, `{"auth_id":5}`, true, 400)
	f.call("POST", url, `not json`, true, 400)
	if f.probes.Load() != 2 {
		t.Fatal("a rejected request polled a provider")
	}
	f.call("GET", url, ``, true, 404)
}

func TestManagementRoutingRefreshQuotaReportsFailuresWithoutChangingAccounts(t *testing.T) {
	const url = "/v8/management/routing/accounts/refresh-quota"
	f := newQuotaRefreshFixture(t)
	f.failure.Store("HTTP 429")
	got := decodeRefresh(t, f.call("POST", url, `{"auth_id":"route-b"}`, true, 200))
	account := got.Accounts[0]
	if account["last_poll_error"] != "HTTP 429" || account["quota_stopped"] != false || account["last_poll_success_at"] != "" {
		t.Fatalf("failed poll entry: %v", account)
	}
	windows := account["windows"].([]any)
	if windows[0].(map[string]any)["remaining_percent"] != nil {
		t.Fatalf("failed poll produced a reading: %v", windows)
	}
}

func TestManagementRoutingRefreshQuotaWhenSessionBalancedIsDisabledOrPollerMissing(t *testing.T) {
	const url = "/v8/management/routing/accounts/refresh-quota"
	f := newQuotaRefreshFixture(t)
	f.manager.SetQuotaPoller(nil)
	f.call("POST", url, `{}`, true, 503)
	f.manager.SetSelector(&coreauth.RoundRobinSelector{})
	// Like the other routing mutations, refresh needs the strategy it feeds.
	f.call("POST", url, `{}`, true, 409)
	f.call("POST", url, `{"auth_id":"route-a"}`, true, 409)
	if f.probes.Load() != 0 {
		t.Fatal("disabled mode polled a provider")
	}
	var snapshot map[string]any
	if err := json.Unmarshal([]byte(f.call("GET", "/v8/management/routing/sessions", "", true, 200)), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot["enabled"] != false || snapshot["short_window_reserve_percent"] != 5.0 || snapshot["long_window_reserve_percent"] != 2.0 || snapshot["quota_poll_interval_seconds"] != 0.0 {
		t.Fatalf("disabled snapshot: %v", snapshot)
	}
	if accounts, ok := snapshot["accounts"].([]any); !ok || len(accounts) != 0 {
		t.Fatalf("disabled snapshot accounts: %v", snapshot["accounts"])
	}
}

func TestManagementRoutingSessionsExposeWindowsAndPollingSettings(t *testing.T) {
	f := newQuotaRefreshFixture(t)
	f.manager.QuotaPoller().Configure(5 * time.Minute)
	f.selector.SetQuotaReserves(coreauth.SessionQuotaReserves{Short: 6, Long: 3})
	f.call("POST", "/v8/management/routing/accounts/refresh-quota", `{"auth_id":"route-a"}`, true, 200)
	var snapshot struct {
		Enabled                   bool             `json:"enabled"`
		QuotaPollIntervalSeconds  int              `json:"quota_poll_interval_seconds"`
		ShortWindowReservePercent float64          `json:"short_window_reserve_percent"`
		LongWindowReservePercent  float64          `json:"long_window_reserve_percent"`
		Accounts                  []map[string]any `json:"accounts"`
	}
	if err := json.Unmarshal([]byte(f.call("GET", "/v8/management/routing/sessions", "", true, 200)), &snapshot); err != nil {
		t.Fatal(err)
	}
	if !snapshot.Enabled || snapshot.QuotaPollIntervalSeconds != 300 || snapshot.ShortWindowReservePercent != 6 || snapshot.LongWindowReservePercent != 3 || len(snapshot.Accounts) != 3 {
		t.Fatalf("snapshot: %+v", snapshot)
	}
	byID := map[string]map[string]any{}
	for _, a := range snapshot.Accounts {
		byID[a["id"].(string)] = a
	}
	// Reserves apply per window: 3% remaining is inside the 6% short reserve.
	if w := byID["route-a"]["windows"].([]any)[0].(map[string]any); w["reserve_percent"] != 6.0 || w["stopped"] != true {
		t.Fatalf("route-a short window: %v", w)
	}
	if w := byID["route-a"]["windows"].([]any)[1].(map[string]any); w["reserve_percent"] != 3.0 || w["stopped"] != false {
		t.Fatalf("route-a long window: %v", w)
	}
	// An API-key credential is listed but has no quota windows and was never polled.
	if w := byID["route-key"]["windows"].([]any); len(w) != 0 || byID["route-key"]["last_poll_at"] != "" {
		t.Fatalf("route-key: %v", byID["route-key"])
	}
	if byID["route-b"]["last_poll_at"] != "" {
		t.Fatalf("route-b was not refreshed: %v", byID["route-b"])
	}
}
