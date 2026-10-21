package auth

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	executor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func reserveObservation(now time.Time, provider, short, long string) QuotaState {
	signals := map[string]string{"x-codex-primary-used-percent": short, "x-codex-secondary-used-percent": long}
	if provider == "claude" {
		signals = map[string]string{"anthropic-ratelimit-unified-5h-utilization": short, "anthropic-ratelimit-unified-7d-utilization": long}
	}
	return QuotaState{ObservedAt: now, Signals: signals}
}

func TestSessionBalancedReserveStopsNewAndExistingSessions(t *testing.T) {
	for _, provider := range []string{"claude", "codex"} {
		for _, existing := range []bool{false, true} {
			for _, window := range []string{"short", "long"} {
				t.Run(provider+"/"+window+"/existing="+map[bool]string{true: "true", false: "false"}[existing], func(t *testing.T) {
					s := NewSessionBalancedSelector("", time.Hour)
					defer s.Stop()
					now := time.Now()
					pool := balancedPool()
					for _, a := range pool {
						a.Provider = provider
					}
					pool[0].Attributes = map[string]string{"priority": "10"}
					if existing {
						balancedPick(t, s, balancedOptions("caller", "session"), pool)
					}
					short, long := "10", "10"
					low := "99"
					if provider == "claude" {
						short, long, low = "0.1", "0.1", "0.99"
					}
					if window == "short" {
						short = low
					} else {
						long = low
					}
					pool[0].Quota = reserveObservation(now, provider, short, long)
					if got := balancedPick(t, s, balancedOptions("caller", "session"), pool); got.ID != "b" {
						t.Fatalf("reserve account selected: %s", got.ID)
					}
					row := s.Snapshot().Sessions[0]
					if existing && (row.Generation != 2 || len(row.Migrations) != 1) {
						t.Fatalf("migration not recorded: %+v", row)
					}
				})
			}
		}
	}
}

func TestSessionBalancedReservePositiveBoundary(t *testing.T) {
	for _, used := range []string{"98.99", "99", "100", "101"} {
		t.Run(used, func(t *testing.T) {
			s := NewSessionBalancedSelector("", time.Hour)
			defer s.Stop()
			pool := balancedPool()
			pool[0].Attributes = map[string]string{"priority": "10"}
			pool[0].Quota = reserveObservation(time.Now(), "codex", "0", used)
			want := "b"
			if used == "98.99" {
				want = "a"
			}
			if got := balancedPick(t, s, balancedOptions("caller", "boundary"), pool); got.ID != want {
				t.Fatalf("used %s: got %s want %s", used, got.ID, want)
			}
		})
	}
}

func TestSessionBalancedReservePersistsThroughPartialStaleAndRestart(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "state")
	pool := balancedPool()
	pool[0].Quota = reserveObservation(now, "codex", "10", "99")
	pool[0].Quota.Signals["x-codex-secondary-reset-at"] = now.Add(time.Hour).Format(time.RFC3339)
	s := NewSessionBalancedSelector(path, time.Hour)
	s.now = func() time.Time { return now }
	if got := balancedPick(t, s, balancedOptions("caller", "one"), pool); got.ID != "b" {
		t.Fatal("weekly reserve ignored")
	}
	s.Stop()
	s = NewSessionBalancedSelector(path, time.Hour)
	defer s.Stop()
	s.now = func() time.Time { return now }
	// A newer response omits the weekly window; the stop must survive it and restart.
	now = now.Add(6 * time.Minute)
	pool[0].Quota = QuotaState{ObservedAt: now, Signals: map[string]string{"x-codex-primary-used-percent": "1"}}
	if got := balancedPick(t, s, balancedOptions("caller", "two"), pool); got.ID != "b" {
		t.Fatal("partial snapshot erased weekly stop")
	}
	pool[0].Quota = QuotaState{}
	if got := balancedPick(t, s, balancedOptions("caller", "three"), pool); got.ID != "b" {
		t.Fatal("missing snapshot erased weekly stop")
	}
	now = now.Add(time.Hour)
	pool[0].Attributes = map[string]string{"priority": "10"}
	if got := balancedPick(t, s, balancedOptions("caller", "after-reset"), pool); got.ID != "a" {
		t.Fatal("reset did not release account")
	}
}

func TestSessionBalancedReserveOnlyNewerHealthyWindowClearsStop(t *testing.T) {
	now := time.Now()
	s := NewSessionBalancedSelector("", time.Hour)
	defer s.Stop()
	s.now = func() time.Time { return now }
	pool := balancedPool()
	pool[0].Attributes = map[string]string{"priority": "10"}
	pool[0].Quota = reserveObservation(now, "codex", "99", "99")
	balancedPick(t, s, balancedOptions("caller", "low"), pool)
	now = now.Add(time.Minute)
	pool[0].Quota = QuotaState{ObservedAt: now, Signals: map[string]string{"x-codex-primary-used-percent": "10"}}
	if got := balancedPick(t, s, balancedOptions("caller", "partial-recovery"), pool); got.ID != "b" {
		t.Fatal("one healthy window cleared another stopped window")
	}
	pool[0].Quota = reserveObservation(now, "codex", "10", "10")
	if got := balancedPick(t, s, balancedOptions("caller", "recovery"), pool); got.ID != "a" {
		t.Fatal("fresh weekly recovery did not release account")
	}
	if got := balancedPick(t, s, balancedOptions("caller", "low"), pool); got.ID != "b" {
		t.Fatal("recovery moved an existing pin back")
	}
}

func TestSessionBalancedReserveResetDoesNotReusePreviousWindowValue(t *testing.T) {
	now := time.Now()
	s := NewSessionBalancedSelector("", time.Hour)
	defer s.Stop()
	s.now = func() time.Time { return now }
	pool := balancedPool()
	pool[0].Attributes = map[string]string{"priority": "10"}
	pool[0].Quota = reserveObservation(now, "codex", "10", "100")
	pool[0].Quota.Signals["x-codex-secondary-reset-at"] = now.Add(time.Minute).Format(time.RFC3339)
	if got := balancedPick(t, s, balancedOptions("caller", "before"), pool); got.ID != "b" {
		t.Fatal("exhausted window accepted")
	}
	now = now.Add(2 * time.Minute)
	if got := balancedPick(t, s, balancedOptions("caller", "after"), pool); got.ID != "a" {
		t.Fatal("previous window value blocked reset quota")
	}
}

func TestSessionBalancedPersistedQuotaStopsValidated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	s := NewSessionBalancedSelector(path, time.Hour)
	s.state.QuotaStops = map[string]map[string]sessionQuotaStop{"a": {"unknown-window": {ObservedAt: time.Now(), Reason: "bad state"}}}
	if err := s.persist(); err != nil {
		t.Fatal(err)
	}
	s.Stop()
	restored := NewSessionBalancedSelector(path, time.Hour)
	defer restored.Stop()
	if _, err := restored.Pick(context.Background(), "codex", "model", balancedOptions("caller", "bad"), balancedPool()); statusCodeFromError(err) != 503 {
		t.Fatalf("invalid stop state accepted: %v", err)
	}
}

func TestSessionBalancedConfirmedQuotaRetainsKnownWindowReset(t *testing.T) {
	now := time.Now()
	s := NewSessionBalancedSelector("", time.Hour)
	defer s.Stop()
	s.now = func() time.Time { return now }
	pool := balancedPool()
	s.accounts = func() []*Auth { return pool }
	first := balancedOptions("caller", "first")
	second := balancedOptions("caller", "second")
	balancedPick(t, s, first, pool[:1])
	balancedPick(t, s, second, pool[:1])
	pool[0].Quota = reserveObservation(now, "codex", "10", "100")
	reset := now.Add(2 * time.Hour).Truncate(time.Second)
	pool[0].Quota.Signals["x-codex-secondary-reset-at"] = reset.Format(time.RFC3339)
	s.OnResult(Result{AuthID: "a", Error: &Error{HTTPStatus: 429, Message: "usage_limit_reached"}, Options: first})
	if stop := s.state.QuotaStops["a"]["confirmed"]; !stop.ResetAt.Equal(reset) {
		t.Fatalf("known reset lost: %+v", stop)
	}
	pool[0].Quota = QuotaState{}
	s.OnResult(Result{AuthID: "a", Error: &Error{HTTPStatus: 429, Message: "usage_limit_reached"}, Options: second})
	if stop := s.state.QuotaStops["a"]["confirmed"]; !stop.ResetAt.Equal(reset) {
		t.Fatal("later error without reset erased known reset")
	}
	now = reset.Add(time.Second)
	pool[0].Attributes = map[string]string{"priority": "10"}
	if got := balancedPick(t, s, balancedOptions("caller", "new-after-reset"), pool); got.ID != "a" {
		t.Fatal("confirmed exhaustion became an indefinite stop")
	}
}

func newReserveTestManager(t *testing.T) (*SessionBalancedSelector, *Manager, []*Auth, *balancedTestExecutor) {
	t.Helper()
	s := NewSessionBalancedSelector(filepath.Join(t.TempDir(), "state"), time.Hour)
	t.Cleanup(s.Stop)
	m := NewManager(nil, s, nil)
	m.SetRetryConfig(0, 0, 0)
	pool := balancedPool()
	for _, a := range pool {
		if _, err := m.Register(context.Background(), a); err != nil {
			t.Fatal(err)
		}
		registry.GetGlobalRegistry().RegisterClient(a.ID, "codex", []*registry.ModelInfo{{ID: "reserve-model"}})
		id := a.ID
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	}
	e := &balancedTestExecutor{}
	m.RegisterExecutor(e)
	return s, m, pool, e
}

func seedReserveSession(t *testing.T, s *SessionBalancedSelector, pool []*Auth, namespace, id string) executor.Options {
	t.Helper()
	o := balancedOptions("caller", id)
	if _, err := s.Pick(context.Background(), namespace, "reserve-model", o, pool[:1]); err != nil {
		t.Fatal(err)
	}
	return o
}

func TestSessionBalancedCredentialQuotaMigratesEveryAffectedSession(t *testing.T) {
	s, m, pool, e := newReserveTestManager(t)
	first := seedReserveSession(t, s, pool, "mixed", "first")
	seedReserveSession(t, s, pool, "mixed", "second")
	retry := time.Hour
	m.MarkResult(context.Background(), Result{AuthID: "a", Provider: "codex", Model: "reserve-model", RouteModel: "reserve-model", Error: &Error{HTTPStatus: 429, Message: "usage_limit_reached"}, CredentialScope: true, RetryAfter: &retry, Options: first})
	for _, id := range []string{"first", "second"} {
		_, err := m.Execute(context.Background(), []string{"codex"}, executor.Request{Model: "reserve-model", Payload: []byte(`{"input":"full history"}`)}, balancedOptions("caller", id))
		if err != nil {
			t.Fatalf("session %s stranded: %v", id, err)
		}
	}
	if len(e.attempts) != 2 || e.attempts[0] != "b" || e.attempts[1] != "b" {
		t.Fatalf("exhausted account attempted: %v", e.attempts)
	}
	for _, row := range s.Snapshot().Sessions {
		if row.AuthID != "b" || row.Generation != 2 || len(row.Migrations) != 1 {
			t.Fatalf("incorrect migration: %+v", row)
		}
	}
}

func TestSessionBalancedTransportPinnedMoveRequiresReconnectThroughManager(t *testing.T) {
	for _, namespace := range []string{"codex", "mixed"} {
		t.Run(namespace, func(t *testing.T) {
			s, m, pool, e := newReserveTestManager(t)
			seedReserveSession(t, s, pool, namespace, "transport")
			row := s.Snapshot().Sessions[0]
			if err := s.RequestMove(row.ID, "b", row.Generation); err != nil {
				t.Fatal(err)
			}
			o := balancedOptions("caller", "transport")
			o.Metadata[executor.PinnedAuthMetadataKey] = "a"
			o.OriginalRequest = []byte(`{"previous_response_id":"old-account-response"}`)
			var err error
			if namespace == "codex" {
				_, err = m.SelectAuth(context.Background(), namespace, "reserve-model", o)
			} else {
				_, err = m.Execute(context.Background(), []string{"codex"}, executor.Request{Model: "reserve-model"}, o)
			}
			if statusCodeFromError(err) != http.StatusConflict {
				t.Fatalf("want reconnect 409, got %v", err)
			}
			if len(e.attempts) != 0 || s.Snapshot().Sessions[0].AuthID != "a" {
				t.Fatal("unsafe continuation executed or moved")
			}
		})
	}
}

func TestSessionBalancedTransportPinNeverExecutesAnotherAccount(t *testing.T) {
	s, m, pool, e := newReserveTestManager(t)
	seedReserveSession(t, s, pool, "mixed", "existing")
	o := balancedOptions("caller", "existing")
	o.Metadata[executor.PinnedAuthMetadataKey] = "b"
	if _, err := m.Execute(context.Background(), []string{"codex"}, executor.Request{Model: "reserve-model"}, o); statusCodeFromError(err) != 409 {
		t.Fatalf("mismatched transport pin: %v", err)
	}
	o = balancedOptions("caller", "new-transport")
	o.Metadata[executor.PinnedAuthMetadataKey] = "b"
	if _, err := m.Execute(context.Background(), []string{"codex"}, executor.Request{Model: "reserve-model"}, o); err != nil {
		t.Fatal(err)
	}
	if len(e.attempts) != 1 || e.attempts[0] != "b" {
		t.Fatalf("transport pin bypassed: %v", e.attempts)
	}
}

func TestSessionBalancedQuotaContinuationPreservesReconnectError(t *testing.T) {
	for _, count := range []bool{false, true} {
		t.Run(map[bool]string{false: "execute", true: "count"}[count], func(t *testing.T) {
			s, m, pool, e := newReserveTestManager(t)
			seedReserveSession(t, s, pool, "mixed", "continuation")
			e.failure = &Error{HTTPStatus: 429, Message: "usage_limit_reached"}
			o := balancedOptions("caller", "continuation")
			o.Metadata[executor.PinnedAuthMetadataKey] = "a"
			o.OriginalRequest = []byte(`{"previous_response_id":"old-response"}`)
			req := executor.Request{Model: "reserve-model", Payload: o.OriginalRequest}
			var err error
			if count {
				_, err = m.ExecuteCount(context.Background(), []string{"codex"}, req, o)
			} else {
				_, err = m.Execute(context.Background(), []string{"codex"}, req, o)
			}
			if !IsSessionReconnectRequired(err) || statusCodeFromError(err) != 409 {
				t.Fatalf("upstream 429 hid reconnect policy: %v", err)
			}
			if len(e.attempts) != 1 || e.attempts[0] != "a" {
				t.Fatalf("delta rotated credentials: %v", e.attempts)
			}
		})
	}
}

func TestSessionBalancedAllStoppedPreservesOwnershipAndManualTargetRejected(t *testing.T) {
	s, m, pool, e := newReserveTestManager(t)
	seedReserveSession(t, s, pool, "mixed", "stopped")
	for _, a := range pool {
		a.Quota = reserveObservation(time.Now(), "codex", "99", "99")
		if _, err := m.Update(context.Background(), a); err != nil {
			t.Fatal(err)
		}
	}
	row := s.Snapshot().Sessions[0]
	if err := s.RequestMove(row.ID, "b", row.Generation); err == nil {
		t.Fatal("manual move allowed quota-stopped target")
	}
	if _, err := m.Execute(context.Background(), []string{"codex"}, executor.Request{Model: "reserve-model"}, balancedOptions("caller", "stopped")); statusCodeFromError(err) != 503 {
		t.Fatalf("all stopped: %v", err)
	}
	if len(e.attempts) != 0 || s.Snapshot().Sessions[0].AuthID != "a" {
		t.Fatal("all-stopped request dispatched or lost ownership")
	}
}
