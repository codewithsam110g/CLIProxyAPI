package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
