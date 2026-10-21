package auth

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	executor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
)

func balancedOptions(scope, id string) executor.Options {
	return executor.Options{Headers: http.Header{"X-Session-Id": {id}}, Metadata: map[string]any{executor.CallerScopeMetadataKey: scope}}
}
func balancedPool() []*Auth {
	return []*Auth{{ID: "a", Provider: "codex"}, {ID: "b", Provider: "codex"}}
}
func balancedPick(t *testing.T, s *SessionBalancedSelector, o executor.Options, pool []*Auth) *Auth {
	t.Helper()
	a, err := s.Pick(context.Background(), "codex", "model", o, pool)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestSessionBalancedAtomicFirstAssignmentAndCallerScope(t *testing.T) {
	s := NewSessionBalancedSelector(filepath.Join(t.TempDir(), "sessions.state"), time.Hour)
	defer s.Stop()
	pool := balancedPool()
	s.accounts = func() []*Auth { return pool }
	start := make(chan struct{})
	results := make(chan string, 32)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			a, err := s.Pick(context.Background(), "codex", "model", balancedOptions("caller-a", "same"), pool)
			if err != nil {
				results <- err.Error()
			} else {
				results <- a.ID
			}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	for id := range results {
		if id != "a" {
			t.Fatalf("split assignment: %s", id)
		}
	}
	if got := balancedPick(t, s, balancedOptions("caller-b", "same"), pool); got.ID != "b" {
		t.Fatalf("caller scopes shared: %s", got.ID)
	}
	if len(s.Snapshot().Sessions) != 2 {
		t.Fatal("expected two independent sessions")
	}
}

func TestSessionBalancedRestartAndTokenRotationPreservePin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.state")
	pool := balancedPool()
	s := NewSessionBalancedSelector(path, time.Hour)
	o := balancedOptions("caller", "s")
	first := balancedPick(t, s, o, pool)
	s.Stop()
	pool[0].Metadata = map[string]any{"access_token": "synthetic-rotated"}
	restored := NewSessionBalancedSelector(path, time.Hour)
	defer restored.Stop()
	if got := balancedPick(t, restored, balancedOptions("caller", "s"), pool); got.ID != first.ID {
		t.Fatal("restart changed account")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("permissions: %v", info.Mode())
	}
	data, _ := os.ReadFile(path)
	if string(data) == "" {
		t.Fatal("state empty")
	}
}

func TestSessionBalancedTransientErrorsNeverUseAlternateAccount(t *testing.T) {
	for _, failure := range []*Error{{HTTPStatus: 500, Message: "overload"}, {HTTPStatus: 429, Message: "request rate limit"}, {HTTPStatus: 403, Message: "model permission"}} {
		t.Run(failure.Message, func(t *testing.T) {
			s := NewSessionBalancedSelector("", time.Hour)
			defer s.Stop()
			pool := balancedPool()
			s.accounts = func() []*Auth { return pool }
			o := balancedOptions("caller", "s")
			balancedPick(t, s, o, pool)
			s.OnResult(Result{AuthID: "a", Error: failure, Options: o})
			if _, err := s.Pick(context.Background(), "codex", "model", balancedOptions("caller", "s"), pool[1:]); err == nil {
				t.Fatal("temporary failure allowed alternate account")
			}
			if got := balancedPick(t, s, balancedOptions("caller", "s"), pool); got.ID != "a" {
				t.Fatal("pin lost")
			}
		})
	}
}

func TestSessionBalancedConfirmedMigrationAndLateResults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.state")
	s := NewSessionBalancedSelector(path, time.Hour)
	defer s.Stop()
	pool := balancedPool()
	old := balancedOptions("caller", "s")
	balancedPick(t, s, old, pool)
	s.OnResult(Result{AuthID: "a", Error: &Error{HTTPStatus: 429, Message: "usage_limit_reached"}, Options: old})
	next := balancedOptions("caller", "s")
	if got := balancedPick(t, s, next, pool); got.ID != "b" {
		t.Fatal("quota did not migrate")
	}
	s.OnResult(Result{AuthID: "a", Error: &Error{HTTPStatus: 401}, Options: old})
	if got := balancedPick(t, s, balancedOptions("caller", "s"), pool); got.ID != "b" {
		t.Fatal("late result or account recovery changed pin")
	}
	row := s.Snapshot().Sessions[0]
	if row.Generation != 2 || len(row.Migrations) != 1 || row.PendingReason != "" {
		t.Fatalf("bad migration: %+v", row)
	}
}

func TestSessionBalancedContinuationRequiresReplayBeforeMigration(t *testing.T) {
	s := NewSessionBalancedSelector("", time.Hour)
	defer s.Stop()
	pool := balancedPool()
	old := balancedOptions("caller", "s")
	balancedPick(t, s, old, pool)
	s.OnResult(Result{AuthID: "a", Error: &Error{HTTPStatus: 401}, Options: old})
	next := balancedOptions("caller", "s")
	next.OriginalRequest = []byte(`{"previous_response_id":"old-account-response"}`)
	if _, err := s.Pick(context.Background(), "codex", "model", next, pool[1:]); statusCodeFromError(err) != 409 {
		t.Fatalf("wanted replay error: %v", err)
	}
	if row := s.Snapshot().Sessions[0]; row.AuthID != "a" || len(row.Migrations) != 0 {
		t.Fatal("unsafe continuation moved")
	}
}

func TestSessionBalancedDrainMoveAndGenerations(t *testing.T) {
	s := NewSessionBalancedSelector("", time.Hour)
	defer s.Stop()
	pool := balancedPool()
	s.accounts = func() []*Auth { return pool }
	balancedPick(t, s, balancedOptions("caller", "s"), pool)
	row := s.Snapshot().Sessions[0]
	if err := s.SetDraining("a", true); err != nil {
		t.Fatal(err)
	}
	if got := balancedPick(t, s, balancedOptions("caller", "s"), pool); got.ID != "a" {
		t.Fatal("drain moved existing session")
	}
	if got := balancedPick(t, s, balancedOptions("caller", "new"), pool); got.ID != "b" {
		t.Fatal("drain allowed new session")
	}
	if err := s.RequestMove(row.ID, "b", row.Generation+1); err == nil {
		t.Fatal("stale generation accepted")
	}
	if err := s.RequestMove(row.ID, "b", row.Generation); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDraining("b", true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pick(context.Background(), "codex", "model", balancedOptions("caller", "s"), pool); err == nil {
		t.Fatal("pending move ignored new drain state")
	}
	if err := s.SetDraining("b", false); err != nil {
		t.Fatal(err)
	}
	if got := balancedPick(t, s, balancedOptions("caller", "s"), pool); got.ID != "b" {
		t.Fatal("manual move not applied")
	}
}

func TestSessionBalancedParentBindingAndQuotaPlacement(t *testing.T) {
	s := NewSessionBalancedSelector("", time.Hour)
	defer s.Stop()
	pool := balancedPool()
	now := time.Now()
	s.now = func() time.Time { return now }
	pool[0].Quota = QuotaState{ObservedAt: now, Signals: map[string]string{"X-Codex-Primary-Used-Percent": "90", "X-Codex-Secondary-Used-Percent": "10"}}
	pool[1].Quota = QuotaState{ObservedAt: now, Signals: map[string]string{"X-Codex-Primary-Used-Percent": "20", "X-Codex-Secondary-Used-Percent": "20"}}
	parent := balancedOptions("caller", "root")
	parent.Headers = http.Header{"X-Claude-Code-Session-Id": {"root"}}
	if got := balancedPick(t, s, parent, pool); got.ID != "b" {
		t.Fatal("did not use bottleneck quota headroom")
	}
	child := balancedOptions("caller", "root")
	child.Headers = http.Header{"X-Claude-Code-Session-Id": {"root"}, "X-Claude-Code-Agent-Id": {"child"}}
	if got := balancedPick(t, s, child, pool); got.ID != "b" {
		t.Fatal("child did not inherit parent")
	}
	other := balancedOptions("other-caller", "root")
	other.Headers = child.Headers
	balancedPick(t, s, other, pool)
	if len(s.Snapshot().Sessions) != 3 {
		t.Fatal("parent or caller session was merged")
	}
}

func TestSessionBalancedCorruptOrUnwritableStateFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.state")
	if err := os.WriteFile(path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	s := NewSessionBalancedSelector(path, time.Hour)
	defer s.Stop()
	if _, err := s.Pick(context.Background(), "codex", "model", balancedOptions("caller", "s"), balancedPool()); err == nil {
		t.Fatal("corrupt state silently reset")
	}
	blocked := filepath.Join(t.TempDir(), "file")
	_ = os.WriteFile(blocked, []byte("x"), 0600)
	s2 := NewSessionBalancedSelector(filepath.Join(blocked, "state"), time.Hour)
	defer s2.Stop()
	if _, err := s2.Pick(context.Background(), "codex", "model", balancedOptions("caller", "s"), balancedPool()); err == nil {
		t.Fatal("unwritable state allowed dispatch")
	}
}

func TestSessionBalancedUsageUsesNonOverlappingBuckets(t *testing.T) {
	s := NewSessionBalancedSelector("", time.Hour)
	defer s.Stop()
	o := balancedOptions("caller", "s")
	balancedPick(t, s, o, balancedPool())
	ctx := balancedExecutionContext(context.Background(), o)
	s.ObserveUsage(ctx, usage.Record{AuthID: "a", Detail: usage.Detail{TokenBreakdown: usage.NewSubsetTokenBreakdown(100, 70, 10, 20, 0, 120)}})
	row := s.Snapshot().Sessions[0]
	if row.InputTokens != 100 || row.CacheReadTokens != 70 || row.CacheWriteTokens != 10 || row.OutputTokens != 20 || row.UsageSamples != 1 {
		t.Fatalf("usage: %+v", row)
	}
}

type balancedTestExecutor struct {
	attempts []string
	failure  *Error
}

func (e *balancedTestExecutor) Identifier() string { return "codex" }
func (e *balancedTestExecutor) Execute(_ context.Context, a *Auth, _ executor.Request, _ executor.Options) (executor.Response, error) {
	e.attempts = append(e.attempts, a.ID)
	if a.ID == "a" && e.failure != nil {
		return executor.Response{}, e.failure
	}
	return executor.Response{Payload: []byte(a.ID)}, nil
}
func (e *balancedTestExecutor) ExecuteStream(context.Context, *Auth, executor.Request, executor.Options) (*executor.StreamResult, error) {
	panic("unused")
}
func (e *balancedTestExecutor) Refresh(_ context.Context, a *Auth) (*Auth, error) { return a, nil }
func (e *balancedTestExecutor) CountTokens(ctx context.Context, a *Auth, r executor.Request, o executor.Options) (executor.Response, error) {
	return e.Execute(ctx, a, r, o)
}
func (e *balancedTestExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	panic("unused")
}

func TestSessionBalancedManagerDoesNotFailOverOnTransientErrors(t *testing.T) {
	s := NewSessionBalancedSelector("", time.Hour)
	defer s.Stop()
	m := NewManager(nil, s, nil)
	m.SetRetryConfig(0, 0, 0)
	for _, a := range balancedPool() {
		_, err := m.Register(context.Background(), a)
		if err != nil {
			t.Fatal(err)
		}
		registry.GetGlobalRegistry().RegisterClient(a.ID, "codex", []*registry.ModelInfo{{ID: "balanced-test-model"}})
		defer registry.GetGlobalRegistry().UnregisterClient(a.ID)
	}
	e := &balancedTestExecutor{failure: &Error{HTTPStatus: 500, Message: "temporary overload"}}
	m.RegisterExecutor(e)
	_, err := m.Execute(context.Background(), []string{"codex"}, executor.Request{Model: "balanced-test-model", Payload: []byte(`{"input":"hi"}`)}, balancedOptions("caller", "manager"))
	if err == nil {
		t.Fatal("expected transient error")
	}
	if len(e.attempts) != 1 || e.attempts[0] != "a" {
		t.Fatalf("cross-account failover: %v", e.attempts)
	}
}

func TestSessionBalancedMigrationIgnoresRecoveredPriority(t *testing.T) {
	s := NewSessionBalancedSelector("", time.Hour)
	defer s.Stop()
	pool := balancedPool()
	pool[0].Attributes = map[string]string{"priority": "10"}
	o := balancedOptions("caller", "priority")
	balancedPick(t, s, o, pool)
	s.OnResult(Result{AuthID: "a", Error: &Error{HTTPStatus: 429, Message: "usage_limit_reached"}, Options: o})
	if got := balancedPick(t, s, balancedOptions("caller", "priority"), pool); got.ID != "b" {
		t.Fatal("old priority prevented migration")
	}
	if got := balancedPick(t, s, balancedOptions("caller", "priority"), pool); got.ID != "b" {
		t.Fatal("recovered higher priority stole session")
	}
}

func TestSessionBalancedManagerMigratesOnlyConfirmedQuota(t *testing.T) {
	for _, tc := range []struct {
		name, message string
		want          int
	}{{"quota", "usage_limit_reached", 2}, {"rate", "request rate limited", 1}} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewSessionBalancedSelector("", time.Hour)
			defer s.Stop()
			m := NewManager(nil, s, nil)
			m.SetRetryConfig(0, 0, 0)
			for _, a := range balancedPool() {
				if _, err := m.Register(context.Background(), a); err != nil {
					t.Fatal(err)
				}
				registry.GetGlobalRegistry().RegisterClient(a.ID, "codex", []*registry.ModelInfo{{ID: "balanced-quota-model"}})
				defer registry.GetGlobalRegistry().UnregisterClient(a.ID)
			}
			e := &balancedTestExecutor{failure: &Error{HTTPStatus: 429, Message: tc.message}}
			m.RegisterExecutor(e)
			_, err := m.Execute(context.Background(), []string{"codex"}, executor.Request{Model: "balanced-quota-model", Payload: []byte(`{"input":"hi"}`)}, balancedOptions("caller", "quota"))
			if len(e.attempts) != tc.want {
				t.Fatalf("attempts=%v error=%v", e.attempts, err)
			}
			if tc.want == 2 && err != nil {
				t.Fatal(err)
			}
			if tc.want == 1 && err == nil {
				t.Fatal("transient failure was hidden")
			}
		})
	}
}

func TestSessionBalancedSelectorReloadKeepsLatestPins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	old := NewSessionBalancedSelector(path, time.Hour)
	m := NewManager(nil, old, nil)
	// Construct the replacement before the old selector's final checkpoint.
	replacement := NewSessionBalancedSelector(path, time.Hour)
	balancedPick(t, old, balancedOptions("caller", "reload"), balancedPool())
	m.SetSelector(replacement)
	defer replacement.Stop()
	if len(replacement.Snapshot().Sessions) != 1 {
		t.Fatal("reload lost latest binding")
	}
	if got := balancedPick(t, replacement, balancedOptions("caller", "reload"), balancedPool()); got.ID != "a" {
		t.Fatal("reload lost latest binding")
	}
}

func TestSessionBalancedQuotaFreshnessAndUnknown(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name, value string
		age         time.Duration
		want        *float64
	}{
		{"stale", "20", 6 * time.Minute, nil}, {"invalid", "NaN", 0, nil}, {"negative", "-1", 0, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &Auth{Quota: QuotaState{ObservedAt: now.Add(-tc.age), Signals: map[string]string{"x-codex-primary-used-percent": tc.value}}}
			got, _ := accountHeadroom(a, now)
			if got != nil {
				t.Fatalf("unknown quota became %v", *got)
			}
		})
	}
}

func TestSessionBalancedDoesNotReplayAfterVisibleStreamOutput(t *testing.T) {
	s := NewSessionBalancedSelector("", time.Hour)
	defer s.Stop()
	m := NewManager(nil, s, nil)
	m.SetRetryConfig(0, 0, 0)
	for _, a := range balancedPool() {
		if _, err := m.Register(context.Background(), a); err != nil {
			t.Fatal(err)
		}
		registry.GetGlobalRegistry().RegisterClient(a.ID, "codex", []*registry.ModelInfo{{ID: "balanced-stream-model"}})
		defer registry.GetGlobalRegistry().UnregisterClient(a.ID)
	}
	var mu sync.Mutex
	var attempts []string
	m.RegisterExecutor(&customStreamMockExecutor{identifier: "codex", streamFn: func(_ context.Context, a *Auth, _ executor.Request, _ executor.Options) (*executor.StreamResult, error) {
		mu.Lock()
		attempts = append(attempts, a.ID)
		mu.Unlock()
		chunks := make(chan executor.StreamChunk, 2)
		chunks <- executor.StreamChunk{Payload: []byte(`data: {"type":"response.output_text.delta","delta":"visible"}` + "\n\n")}
		chunks <- executor.StreamChunk{Err: &Error{HTTPStatus: 429, Message: "usage_limit_reached"}}
		close(chunks)
		return &executor.StreamResult{Chunks: chunks}, nil
	}})
	stream, err := m.ExecuteStream(context.Background(), []string{"codex"}, executor.Request{Model: "balanced-stream-model", Payload: []byte(`{"input":"hi"}`)}, balancedOptions("caller", "stream"))
	if err != nil {
		t.Fatal(err)
	}
	visible, failed := false, false
	for c := range stream.Chunks {
		visible = visible || len(c.Payload) > 0
		failed = failed || c.Err != nil
	}
	if !visible || !failed {
		t.Fatal("expected visible output followed by a terminal error")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(attempts) != 1 || attempts[0] != "a" {
		t.Fatalf("partial stream was replayed: %v", attempts)
	}
}

func TestSessionBalancedPluginCannotBypassPins(t *testing.T) {
	s := NewSessionBalancedSelector("", time.Hour)
	defer s.Stop()
	m := NewManager(nil, s, nil)
	plugin := &fakePluginScheduler{handled: true}
	if _, handled, err := m.pickViaPluginScheduler(context.Background(), plugin, "codex", []string{"codex"}, "model", balancedOptions("caller", "plugin"), nil, balancedPool()); err != nil || handled || plugin.calls != 0 {
		t.Fatalf("plugin bypassed routing ownership: handled=%v calls=%d error=%v", handled, plugin.calls, err)
	}
}

func TestSessionBalancedCannotBypassPinsWithCreditsFallback(t *testing.T) {
	s := NewSessionBalancedSelector("", time.Hour)
	defer s.Stop()
	m := NewManager(nil, s, nil)
	m.runtimeConfig.Store(&internalconfig.Config{QuotaExceeded: internalconfig.QuotaExceeded{AntigravityCredits: true}})
	if shouldAttemptAntigravityCreditsFallback(m, &Error{HTTPStatus: 429, Message: "usage_limit_reached"}, []string{"antigravity"}) {
		t.Fatal("credits fallback can bypass pins")
	}
}
