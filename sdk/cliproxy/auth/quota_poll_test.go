package auth

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	executor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// recv waits for a value; the timeout only bounds a failing test.
func recv[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		panic("unreachable")
	}
}

type pollClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *pollClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *pollClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type pollProbeCall struct{ authID, token string }

// fakePollProbe is a QuotaProbe that records calls and can hold them in flight.
type fakePollProbe struct {
	mu      sync.Mutex
	calls   []pollProbeCall
	result  func(pollProbeCall) (map[string]string, error)
	entered chan pollProbeCall
	// block holds calls for these account IDs until release is closed or ctx ends.
	block   map[string]bool
	release chan struct{}
}

func (p *fakePollProbe) probe(ctx context.Context, auth *Auth, token string) (map[string]string, error) {
	call := pollProbeCall{authID: auth.ID, token: token}
	p.mu.Lock()
	p.calls = append(p.calls, call)
	result, block, release := p.result, p.block[auth.ID], p.release
	p.mu.Unlock()
	p.entered <- call
	if block {
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return result(call)
}

func (p *fakePollProbe) count(authID string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, c := range p.calls {
		if c.authID == authID {
			n++
		}
	}
	return n
}

func fmtPercent(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

func codexPoll(shortRemaining, longRemaining float64) map[string]string {
	return map[string]string{
		"X-Codex-Primary-Used-Percent":   fmtPercent(100 - shortRemaining),
		"X-Codex-Secondary-Used-Percent": fmtPercent(100 - longRemaining),
	}
}

func oauthAuth(id, provider string, expires time.Time) *Auth {
	return &Auth{ID: id, Provider: provider, Metadata: map[string]any{"access_token": "tok-" + id, "expired": expires.Format(time.RFC3339)}}
}

type pollFixture struct {
	clock    *pollClock
	selector *SessionBalancedSelector
	manager  *Manager
	poller   *QuotaPoller
	probe    *fakePollProbe
}

func newPollFixture(t *testing.T, auths ...*Auth) *pollFixture {
	t.Helper()
	clock := &pollClock{now: time.Now().Truncate(time.Second)}
	selector := NewSessionBalancedSelector("", time.Hour)
	selector.now = clock.Now
	t.Cleanup(selector.Stop)
	manager := NewManager(nil, selector, nil)
	for _, a := range auths {
		if _, err := manager.Register(context.Background(), a); err != nil {
			t.Fatal(err)
		}
	}
	probe := &fakePollProbe{entered: make(chan pollProbeCall, 64), result: func(pollProbeCall) (map[string]string, error) { return codexPoll(50, 50), nil }}
	poller := NewQuotaPoller(manager, map[string]QuotaProbe{"codex": probe.probe, "claude": probe.probe})
	poller.now = clock.Now
	manager.SetQuotaPoller(poller)
	t.Cleanup(poller.Stop)
	return &pollFixture{clock: clock, selector: selector, manager: manager, poller: poller, probe: probe}
}

func (f *pollFixture) auth(t *testing.T, id string) *Auth {
	t.Helper()
	a, ok := f.manager.GetByID(id)
	if !ok {
		t.Fatalf("auth %s missing", id)
	}
	return a
}

func (f *pollFixture) account(t *testing.T, id string) RoutingAccount {
	t.Helper()
	for _, a := range f.selector.Snapshot().Accounts {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("account %s missing", id)
	return RoutingAccount{}
}

func (f *pollFixture) mutate(id string, fn func(*Auth)) {
	f.manager.mu.Lock()
	defer f.manager.mu.Unlock()
	fn(f.manager.auths[id])
}

func (f *pollFixture) refresh(t *testing.T, ids ...string) []QuotaRefreshResult {
	t.Helper()
	results, err := f.poller.RefreshQuota(context.Background(), ids...)
	if err != nil {
		t.Fatal(err)
	}
	return results
}

func TestQuotaPollerRecordsObservationAndStopsAccount(t *testing.T) {
	soon := time.Now().Add(time.Hour)
	a := oauthAuth("a", "codex", soon)
	a.Attributes = map[string]string{"priority": "10"}
	f := newPollFixture(t, a, oauthAuth("b", "codex", soon))
	f.probe.result = func(c pollProbeCall) (map[string]string, error) {
		if c.authID == "a" {
			return codexPoll(3, 80), nil
		}
		return codexPoll(60, 60), nil
	}
	f.poller.Configure(5 * time.Minute)
	if _, err := f.selector.Pick(context.Background(), "codex", "model", balancedOptions("caller", "s"), f.manager.List()); err != nil {
		t.Fatal(err)
	}
	results := f.refresh(t)
	if len(results) != 2 || results[0].AuthID != "a" || results[1].AuthID != "b" || results[0].Error != "" || results[0].Coalesced {
		t.Fatalf("results: %+v", results)
	}
	got := f.auth(t, "a")
	if got.Quota.Signals["X-Codex-Primary-Used-Percent"] != "97" || got.Quota.Signals["X-Codex-Secondary-Used-Percent"] != "20" || !got.Quota.ObservedAt.Equal(f.clock.Now()) {
		t.Fatalf("observation not recorded: %+v", got.Quota)
	}
	for _, c := range f.probe.calls {
		if c.token != "tok-"+c.authID {
			t.Fatalf("probe for %s got token %q", c.authID, c.token)
		}
	}
	// The selector re-evaluated immediately: no request had to arrive first.
	entry := f.account(t, "a")
	if !entry.QuotaStopped || entry.QuotaStopReason != "5-hour window at 3% remaining (reserve 5%)" {
		t.Fatalf("stop not applied after poll: %+v", entry)
	}
	if f.account(t, "b").QuotaStopped {
		t.Fatal("healthy account stopped")
	}
	if entry.LastPollAt != f.clock.Now().UTC().Format(time.RFC3339) || entry.LastPollSuccessAt != entry.LastPollAt || entry.LastPollError != "" {
		t.Fatalf("poll status: %+v", entry)
	}
	if snapshot := f.selector.Snapshot(); snapshot.QuotaPollIntervalSeconds != 300 {
		t.Fatalf("snapshot interval = %d", snapshot.QuotaPollIntervalSeconds)
	}
	// The bound conversation migrates on its next safe request.
	next, err := f.selector.Pick(context.Background(), "codex", "model", balancedOptions("caller", "s"), f.manager.List())
	if err != nil || next.ID != "b" {
		t.Fatalf("pinned conversation did not migrate: %v %v", next, err)
	}
}

func TestQuotaPollFailureKeepsLastObservationAndNeverStopsAccount(t *testing.T) {
	f := newPollFixture(t, oauthAuth("a", "codex", time.Now().Add(time.Hour)))
	f.refresh(t)
	before := f.auth(t, "a")
	firstPoll := f.clock.Now()
	if before.Quota.ObservedAt.IsZero() {
		t.Fatal("setup: no observation")
	}
	f.clock.Advance(time.Minute)
	f.probe.result = func(pollProbeCall) (map[string]string, error) { return nil, errors.New("HTTP 429") }
	if results := f.refresh(t); results[0].Error != "HTTP 429" {
		t.Fatalf("failure not reported: %+v", results)
	}
	after := f.auth(t, "a")
	if !reflect.DeepEqual(after.Quota, before.Quota) {
		t.Fatalf("failed poll changed the observation:\nbefore %+v\nafter  %+v", before.Quota, after.Quota)
	}
	if after.Unavailable || after.Status != before.Status || after.Quota.Exceeded || after.LastError != nil || after.StatusMessage != "" {
		t.Fatalf("failed poll changed availability: %+v", after)
	}
	entry := f.account(t, "a")
	if entry.QuotaStopped || entry.LastPollError != "HTTP 429" || entry.LastPollAt != f.clock.Now().UTC().Format(time.RFC3339) || entry.LastPollSuccessAt != firstPoll.UTC().Format(time.RFC3339) {
		t.Fatalf("status after failure: %+v", entry)
	}

	// An unparseable or empty result is a failure too, not an empty observation.
	f.clock.Advance(time.Minute)
	f.probe.result = func(pollProbeCall) (map[string]string, error) { return map[string]string{"X-Unrelated": "1"}, nil }
	if results := f.refresh(t); results[0].Error != "no usage windows in response" {
		t.Fatalf("empty result accepted: %+v", results)
	}
	if !reflect.DeepEqual(f.auth(t, "a").Quota, before.Quota) {
		t.Fatal("empty poll replaced the observation")
	}

	// A failure never releases an existing stop either.
	f.clock.Advance(time.Minute)
	f.probe.result = func(pollProbeCall) (map[string]string, error) { return codexPoll(1, 50), nil }
	f.refresh(t)
	if !f.account(t, "a").QuotaStopped {
		t.Fatal("setup: expected a stop")
	}
	f.clock.Advance(time.Minute)
	f.probe.result = func(pollProbeCall) (map[string]string, error) { return nil, errors.New("request failed") }
	f.refresh(t)
	if entry = f.account(t, "a"); !entry.QuotaStopped || entry.LastPollError != "request failed" {
		t.Fatalf("failed poll released the stop: %+v", entry)
	}
	// Recovery clears the error and keeps the success time current.
	f.clock.Advance(time.Minute)
	f.probe.result = func(pollProbeCall) (map[string]string, error) { return codexPoll(90, 90), nil }
	f.refresh(t)
	if entry = f.account(t, "a"); entry.QuotaStopped || entry.LastPollError != "" || entry.LastPollSuccessAt != entry.LastPollAt {
		t.Fatalf("success after failure: %+v", entry)
	}
}

func TestMergePolledQuotaSignals(t *testing.T) {
	for _, tc := range []struct {
		name     string
		provider string
		existing map[string]string
		polled   map[string]string
		want     map[string]string
	}{
		{
			name:     "codex replaces owned window signals and keeps the rest",
			provider: "codex",
			existing: map[string]string{
				"X-Codex-Primary-Used-Percent":                  "10",
				"X-Codex-Primary-Reset-At":                      "111",
				"X-Codex-Secondary-Used-Percent":                "20",
				"X-Codex-Secondary-Window-Minutes":              "10080",
				"X-Codex-Limit-Reached":                         "true",
				"X-Codex-Allowed":                               "false",
				"Retry-After":                                   "30",
				"X-Codex-Plan-Type":                             "plus",
				"X-Codex-Credits-Balance":                       "5",
				"X-Codex-Active-Limit":                          "codex",
				"X-Codex-Bengalfox-Primary-Used-Percent":        "40",
				"X-Codex-Additional-Spark-Primary-Used-Percent": "41",
			},
			polled: map[string]string{
				"X-Codex-Primary-Used-Percent": "30",
				"X-Codex-Primary-Reset-At":     "222",
				"X-Codex-Plan-Type":            "pro",
			},
			want: map[string]string{
				"X-Codex-Primary-Used-Percent":                  "30",
				"X-Codex-Primary-Reset-At":                      "222",
				"X-Codex-Plan-Type":                             "pro",
				"X-Codex-Credits-Balance":                       "5",
				"X-Codex-Active-Limit":                          "codex",
				"X-Codex-Bengalfox-Primary-Used-Percent":        "40",
				"X-Codex-Additional-Spark-Primary-Used-Percent": "41",
			},
		},
		{
			name:     "claude replaces the whole unified family and retry-after",
			provider: "claude",
			existing: map[string]string{
				"Anthropic-Ratelimit-Unified-5h-Utilization": "0.1",
				"Anthropic-Ratelimit-Unified-7d-Utilization": "0.2",
				"Anthropic-Ratelimit-Unified-7d-Reset":       "999",
				"Anthropic-Ratelimit-Unified-Status":         "rejected",
				"Retry-After":                                "60",
			},
			polled: map[string]string{"Anthropic-Ratelimit-Unified-5h-Utilization": "0.4", "Anthropic-Ratelimit-Unified-5h-Reset": "555"},
			want:   map[string]string{"Anthropic-Ratelimit-Unified-5h-Utilization": "0.4", "Anthropic-Ratelimit-Unified-5h-Reset": "555"},
		},
		{
			name:     "lower-case stored keys are matched case-insensitively",
			provider: "codex",
			existing: map[string]string{"x-codex-primary-used-percent": "10", "x-codex-plan-type": "plus"},
			polled:   map[string]string{"X-Codex-Primary-Used-Percent": "70"},
			want:     map[string]string{"X-Codex-Primary-Used-Percent": "70", "X-Codex-Plan-Type": "plus"},
		},
		{
			name:     "no prior snapshot",
			provider: "codex",
			polled:   map[string]string{"X-Codex-Primary-Used-Percent": "70"},
			want:     map[string]string{"X-Codex-Primary-Used-Percent": "70"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mergePolledQuotaSignals(tc.provider, tc.existing, tc.polled); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("merged = %v\nwant     %v", got, tc.want)
			}
		})
	}
}

func TestQuotaPollMergesWithHeaderObservationsWithoutTouchingCooldownFields(t *testing.T) {
	f := newPollFixture(t, oauthAuth("a", "codex", time.Now().Add(time.Hour)))
	recovery := f.clock.Now().Add(time.Hour)
	f.mutate("a", func(a *Auth) {
		a.Quota = QuotaState{Exceeded: true, Reason: "credential_quota", NextRecoverAt: recovery, BackoffLevel: 3}
		a.Quota.ObserveResponseHeadersForProvider("codex", http.Header{
			"X-Codex-Primary-Used-Percent":   {"10"},
			"X-Codex-Secondary-Used-Percent": {"20"},
			"X-Codex-Plan-Type":              {"plus"},
			"X-Codex-Limit-Reached":          {"true"},
			"Retry-After":                    {"30"},
		}, f.clock.Now().Add(-time.Minute))
	})
	before := f.auth(t, "a")
	f.probe.result = func(pollProbeCall) (map[string]string, error) {
		return map[string]string{"X-Codex-Primary-Used-Percent": "55"}, nil // no secondary window
	}
	f.refresh(t)
	after := f.auth(t, "a")
	want := map[string]string{"X-Codex-Primary-Used-Percent": "55", "X-Codex-Plan-Type": "plus"}
	if !reflect.DeepEqual(after.Quota.Signals, want) {
		t.Fatalf("signals = %v, want %v (omitted window and stale flags must not survive under a fresh timestamp)", after.Quota.Signals, want)
	}
	if !after.Quota.ObservedAt.Equal(f.clock.Now()) {
		t.Fatalf("observed at %v", after.Quota.ObservedAt)
	}
	if after.Quota.Exceeded != true || after.Quota.Reason != "credential_quota" || !after.Quota.NextRecoverAt.Equal(recovery) || after.Quota.BackoffLevel != 3 {
		t.Fatalf("poll changed cooldown fields: %+v", after.Quota)
	}
	if after.Generation <= before.Generation {
		t.Fatalf("generation did not advance: %d -> %d", before.Generation, after.Generation)
	}
	// The scheduler's copy must see the new observation too, or placement keeps scoring the old one.
	if f.manager.scheduler != nil {
		if got := f.account(t, "a").ObservedAt; !got.Equal(f.clock.Now()) {
			t.Fatalf("snapshot observed at %v", got)
		}
	}
}

func TestQuotaPollDroppedWhenNewerResponseObservationArrivesInFlight(t *testing.T) {
	f := newPollFixture(t, oauthAuth("a", "codex", time.Now().Add(time.Hour)))
	f.probe.block = map[string]bool{"a": true}
	f.probe.release = make(chan struct{})
	f.probe.result = func(pollProbeCall) (map[string]string, error) { return codexPoll(1, 1), nil }
	done := make(chan []QuotaRefreshResult, 1)
	go func() {
		results, _ := f.poller.RefreshQuota(context.Background(), "a")
		done <- results
	}()
	recv(t, f.probe.entered, "probe to start")
	f.clock.Advance(time.Second)
	f.mutate("a", func(a *Auth) {
		a.Quota.ObserveResponseHeadersForProvider("codex", http.Header{"X-Codex-Primary-Used-Percent": {"10"}, "X-Codex-Secondary-Used-Percent": {"10"}}, f.clock.Now())
	})
	close(f.probe.release)
	if results := recv(t, done, "refresh"); results[0].Error != "" {
		t.Fatalf("overtaken poll is not an error: %+v", results)
	}
	got := f.auth(t, "a")
	if got.Quota.Signals["X-Codex-Primary-Used-Percent"] != "10" {
		t.Fatalf("older poll overwrote the newer response observation: %v", got.Quota.Signals)
	}
	if f.account(t, "a").QuotaStopped {
		t.Fatal("dropped poll stopped the account")
	}
}

func TestQuotaPollerOneInFlightPollPerAccount(t *testing.T) {
	soon := time.Now().Add(time.Hour)
	f := newPollFixture(t, oauthAuth("a", "codex", soon), oauthAuth("b", "codex", soon))
	f.probe.block = map[string]bool{"a": true}
	f.probe.release = make(chan struct{})
	first := make(chan []QuotaRefreshResult, 1)
	go func() {
		results, _ := f.poller.RefreshQuota(context.Background(), "a")
		first <- results
	}()
	if got := recv(t, f.probe.entered, "first probe"); got.authID != "a" {
		t.Fatalf("unexpected first probe %+v", got)
	}
	// A tick while a's poll is still running skips a, but other accounts are unaffected.
	f.poller.PollAllAsync()
	if got := recv(t, f.probe.entered, "b's probe"); got.authID != "b" {
		t.Fatalf("tick polled %s while a was in flight", got.authID)
	}
	// An explicit refresh joins the running poll instead of starting another.
	joined := make(chan []QuotaRefreshResult, 1)
	go func() {
		results, _ := f.poller.RefreshQuota(context.Background(), "a")
		joined <- results
	}()
	close(f.probe.release)
	recv(t, first, "first refresh")
	recv(t, joined, "joined refresh")
	f.poller.Stop() // waits for every poll goroutine, so the counts are final
	if n := f.probe.count("a"); n != 1 {
		t.Fatalf("account a probed %d times, want exactly one in-flight poll", n)
	}
	if n := f.probe.count("b"); n != 1 {
		t.Fatalf("account b probed %d times", n)
	}
}

func TestQuotaRefreshCoalescesRecentPolls(t *testing.T) {
	f := newPollFixture(t, oauthAuth("a", "codex", time.Now().Add(time.Hour)))
	if results := f.refresh(t, "a"); results[0].Coalesced {
		t.Fatalf("first refresh coalesced: %+v", results)
	}
	f.clock.Advance(14 * time.Second)
	if results := f.refresh(t, "a"); !results[0].Coalesced || results[0].Error != "" {
		t.Fatalf("refresh within 15s must reuse the finished poll: %+v", results)
	}
	if f.probe.count("a") != 1 {
		t.Fatal("coalesced refresh called the provider")
	}
	f.clock.Advance(time.Second)
	if results := f.refresh(t, "a"); results[0].Coalesced {
		t.Fatalf("refresh at 15s must poll again: %+v", results)
	}
	// A coalesced reply reports the failure of the poll it reused.
	f.clock.Advance(time.Minute)
	f.probe.result = func(pollProbeCall) (map[string]string, error) { return nil, errors.New("HTTP 403") }
	f.refresh(t, "a")
	f.clock.Advance(time.Second)
	if results := f.refresh(t, "a"); !results[0].Coalesced || results[0].Error != "HTTP 403" {
		t.Fatalf("coalesced reply lost the error: %+v", results)
	}
	if f.probe.count("a") != 3 {
		t.Fatalf("probe calls = %d", f.probe.count("a"))
	}
}

func TestQuotaPollerEligibility(t *testing.T) {
	soon := time.Now().Add(time.Hour)
	disabled := oauthAuth("disabled", "codex", soon)
	disabled.Disabled = true
	disabled.Status = StatusDisabled
	f := newPollFixture(t,
		oauthAuth("a", "codex", soon),
		oauthAuth("c", "claude", soon),
		&Auth{ID: "apikey", Provider: "claude", Attributes: map[string]string{"api_key": "sk-ant-synthetic"}},
		disabled,
		oauthAuth("gemini", "gemini", soon),
		oauthAuth("dead", "codex", soon),
	)
	f.mutate("dead", func(a *Auth) {
		a.Unavailable, a.Status = true, StatusError
		a.LastError = &Error{Code: "unauthorized", HTTPStatus: 401}
	})
	results := f.refresh(t)
	var ids []string
	for _, r := range results {
		ids = append(ids, r.AuthID)
	}
	if !reflect.DeepEqual(ids, []string{"a", "c"}) {
		t.Fatalf("polled %v, want only the Claude/Codex OAuth accounts that can be polled", ids)
	}
	if _, err := f.poller.RefreshQuota(context.Background(), "missing"); !errors.Is(err, ErrQuotaPollAuthNotFound) {
		t.Fatalf("unknown account: %v", err)
	}
	for _, id := range []string{"apikey", "disabled", "gemini", "dead"} {
		if _, err := f.poller.RefreshQuota(context.Background(), id); !errors.Is(err, ErrQuotaPollUnsupported) {
			t.Fatalf("%s: %v", id, err)
		}
	}
	// A bad id anywhere in a request rejects it before any account is polled.
	before := len(f.probe.calls)
	f.clock.Advance(time.Minute)
	if _, err := f.poller.RefreshQuota(context.Background(), "a", "missing"); err == nil || len(f.probe.calls) != before {
		t.Fatalf("partial refresh: %v", err)
	}
}

type pollRefreshExecutor struct {
	refreshed atomic.Int32
	fail      bool
}

func (e *pollRefreshExecutor) Identifier() string { return "codex" }
func (e *pollRefreshExecutor) Execute(context.Context, *Auth, executor.Request, executor.Options) (executor.Response, error) {
	panic("unused")
}
func (e *pollRefreshExecutor) ExecuteStream(context.Context, *Auth, executor.Request, executor.Options) (*executor.StreamResult, error) {
	panic("unused")
}
func (e *pollRefreshExecutor) Refresh(_ context.Context, a *Auth) (*Auth, error) {
	e.refreshed.Add(1)
	if e.fail {
		return nil, errors.New("refresh rejected tok-secret-refresh-detail")
	}
	updated := a.Clone()
	updated.Metadata["access_token"] = "tok-refreshed"
	updated.Metadata["expired"] = time.Now().Add(time.Hour).Format(time.RFC3339)
	return updated, nil
}
func (e *pollRefreshExecutor) CountTokens(context.Context, *Auth, executor.Request, executor.Options) (executor.Response, error) {
	panic("unused")
}
func (e *pollRefreshExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	panic("unused")
}

func TestQuotaPollerAccessTokenAcquisition(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	soon := time.Now().Add(time.Hour)
	expired := oauthAuth("expired", "codex", past)
	expired.Metadata["refresh_token"] = "refresh-expired"
	noRefresh := oauthAuth("norefresh", "codex", past)
	noToken := &Auth{ID: "notoken", Provider: "codex", Metadata: map[string]any{"email": "synthetic@example.test"}}
	f := newPollFixture(t, oauthAuth("valid", "codex", soon), expired, noRefresh, noToken)
	exec := &pollRefreshExecutor{}
	f.manager.RegisterExecutor(exec)

	results := f.refresh(t)
	byID := map[string]QuotaRefreshResult{}
	for _, r := range results {
		byID[r.AuthID] = r
	}
	if byID["valid"].Error != "" || byID["expired"].Error != "" {
		t.Fatalf("results: %+v", results)
	}
	if byID["norefresh"].Error != "access token expired" || byID["notoken"].Error != "no access token" {
		t.Fatalf("results: %+v", results)
	}
	tokens := map[string]string{}
	for _, c := range f.probe.calls {
		tokens[c.authID] = c.token
	}
	if tokens["valid"] != "tok-valid" || tokens["expired"] != "tok-refreshed" || tokens["norefresh"] != "" || tokens["notoken"] != "" {
		t.Fatalf("probe tokens: %v", tokens)
	}
	if exec.refreshed.Load() != 1 {
		t.Fatalf("refresh path used %d times; a valid token must not be refreshed", exec.refreshed.Load())
	}

	// A failed refresh is a failed poll, with no provider text in the stored error.
	failing := newPollFixture(t, expiredCopy("expired2", past))
	failing.manager.RegisterExecutor(&pollRefreshExecutor{fail: true})
	r := failing.refresh(t)[0]
	if r.Error != "token refresh failed" || strings.Contains(r.Error, "secret") || failing.probe.count("expired2") != 0 {
		t.Fatalf("failed refresh: %+v", r)
	}
	if failing.account(t, "expired2").LastPollError != "token refresh failed" {
		t.Fatal("status lost the refresh failure")
	}
}

func expiredCopy(id string, past time.Time) *Auth {
	a := oauthAuth(id, "codex", past)
	a.Metadata["refresh_token"] = "refresh-" + id
	return a
}

func TestQuotaPollErrorTextIsShortAndClean(t *testing.T) {
	if got := quotaPollErrorText(errors.New("bad\nline\x00 with\tcontrols")); strings.ContainsAny(got, "\n\x00\t") {
		t.Fatalf("control characters survived: %q", got)
	}
	if got := quotaPollErrorText(errors.New(strings.Repeat("x", 500))); len(got) != maxQuotaPollErrorLength {
		t.Fatalf("length = %d", len(got))
	}
	if got := quotaPollErrorText(errors.New("  ")); got != "poll failed" {
		t.Fatalf("blank error = %q", got)
	}
}

type fakeQuotaTimer struct {
	d       time.Duration
	fire    chan time.Time
	stopped chan struct{}
}

type fakeQuotaTimers struct{ scheduled chan *fakeQuotaTimer }

func (f *fakeQuotaTimers) after(d time.Duration) (<-chan time.Time, func()) {
	timer := &fakeQuotaTimer{d: d, fire: make(chan time.Time, 1), stopped: make(chan struct{})}
	var once sync.Once
	f.scheduled <- timer
	return timer.fire, func() { once.Do(func() { close(timer.stopped) }) }
}

func TestQuotaPollerLoopFollowsConfigurationWithoutWallClockWaits(t *testing.T) {
	f := newPollFixture(t, oauthAuth("a", "codex", time.Now().Add(time.Hour)))
	timers := &fakeQuotaTimers{scheduled: make(chan *fakeQuotaTimer, 32)}
	f.poller.after = timers.after

	if f.poller.Interval() != 0 {
		t.Fatal("polling must be off until configured")
	}
	f.poller.Configure(5 * time.Minute)
	f.poller.Start()
	f.poller.Start() // idempotent

	// Enabling polling schedules an immediate first poll, then the regular cadence.
	first := recv(t, timers.scheduled, "first timer")
	if first.d != 0 {
		t.Fatalf("first poll delay = %v, want immediate", first.d)
	}
	first.fire <- f.clock.Now()
	recv(t, f.probe.entered, "first scheduled poll")
	cadence := recv(t, timers.scheduled, "cadence timer")
	if cadence.d != 5*time.Minute {
		t.Fatalf("cadence = %v", cadence.d)
	}
	// Joins the scheduled poll if it is still running (or reuses it once finished),
	// so the poll is complete before the clock moves.
	if r := f.refresh(t, "a"); r[0].Error != "" || f.probe.count("a") != 1 {
		t.Fatalf("scheduled poll: %+v calls=%d", r, f.probe.count("a"))
	}

	// Changing the interval re-arms the timer without polling right away.
	f.poller.Configure(3 * time.Minute)
	recv(t, cadence.stopped, "old timer to be stopped")
	changed := recv(t, timers.scheduled, "re-armed timer")
	if changed.d != 3*time.Minute || f.probe.count("a") != 1 {
		t.Fatalf("interval change: delay=%v polls=%d", changed.d, f.probe.count("a"))
	}

	// Disabling stops the loop from scheduling anything; a stale timer is ignored.
	f.poller.Configure(0)
	recv(t, changed.stopped, "timer to be stopped on disable")
	changed.fire <- f.clock.Now()
	if f.poller.Interval() != 0 {
		t.Fatal("interval not disabled")
	}
	// Explicit refreshes still work while background polling is off.
	f.clock.Advance(time.Minute)
	if r := f.refresh(t, "a"); r[0].Error != "" {
		t.Fatalf("manual refresh while disabled: %+v", r)
	}
	recv(t, f.probe.entered, "manual poll")
	if f.probe.count("a") != 2 {
		t.Fatalf("a polled %d times; the stale timer must not poll while disabled", f.probe.count("a"))
	}

	// Re-enabling polls immediately again.
	f.poller.Configure(2 * time.Minute)
	if again := recv(t, timers.scheduled, "timer after re-enable"); again.d != 0 {
		t.Fatalf("re-enable delay = %v", again.d)
	}

	f.poller.Stop()
	if _, err := f.poller.RefreshQuota(context.Background(), "a"); !errors.Is(err, ErrQuotaPollerStopped) {
		t.Fatalf("refresh after Stop: %v", err)
	}
	f.poller.PollAllAsync() // must not panic or start work after Stop
}

func TestQuotaPollerStopCancelsInFlightPollWithoutRecordingAnError(t *testing.T) {
	f := newPollFixture(t, oauthAuth("a", "codex", time.Now().Add(time.Hour)))
	f.probe.block = map[string]bool{"a": true}
	f.probe.release = make(chan struct{})
	f.poller.Start()
	f.poller.PollAllAsync()
	recv(t, f.probe.entered, "probe to start")
	f.poller.Stop() // ctx cancellation ends the held probe; Stop returns once it did
	if status := f.poller.QuotaPollStatus("a"); status.LastError != "" || !status.LastPollAt.IsZero() {
		t.Fatalf("shutdown was recorded as a poll result: %+v", status)
	}
}

func TestQuotaPollDoesNotResurrectConfirmedQuotaExceptThroughRecoveryRules(t *testing.T) {
	f := newPollFixture(t, oauthAuth("a", "codex", time.Now().Add(time.Hour)))
	f.probe.result = func(pollProbeCall) (map[string]string, error) { return codexPoll(90, 90), nil }
	recovery := f.clock.Now().Add(time.Hour)
	f.mutate("a", func(a *Auth) {
		a.Quota.Exceeded, a.Quota.Reason, a.Quota.NextRecoverAt = true, "credential_quota", recovery
	})
	f.selector.RefreshQuotaStops()
	if !f.account(t, "a").QuotaStopped {
		t.Fatal("setup: confirmed credential quota should stop the account")
	}

	// Healthy usage numbers do not override an active credential cooldown.
	f.clock.Advance(20 * time.Second)
	f.refresh(t)
	entry := f.account(t, "a")
	if !entry.QuotaStopped || entry.QuotaStopReason != "confirmed credential quota" {
		t.Fatalf("healthy poll resurrected an account in credential-quota cooldown: %+v", entry)
	}
	if f.auth(t, "a").Quota.Exceeded != true {
		t.Fatal("poll cleared the cooldown fields")
	}

	// Only the existing recovery rule releases it: the cooldown is over and a
	// newer fresh observation shows every window healthy.
	f.mutate("a", func(a *Auth) { a.Quota.Exceeded = false })
	f.clock.Advance(20 * time.Second)
	f.refresh(t)
	if entry = f.account(t, "a"); entry.QuotaStopped {
		t.Fatalf("recovery rules did not release the stop: %+v", entry)
	}
}

func TestQuotaPollAppliesWithoutSessionBalancedSelector(t *testing.T) {
	m := NewManager(nil, &RoundRobinSelector{}, nil)
	if _, err := m.Register(context.Background(), oauthAuth("a", "codex", time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	probe := &fakePollProbe{entered: make(chan pollProbeCall, 4), result: func(pollProbeCall) (map[string]string, error) { return codexPoll(2, 2), nil }}
	p := NewQuotaPoller(m, map[string]QuotaProbe{"codex": probe.probe})
	m.SetQuotaPoller(p)
	defer p.Stop()
	if _, err := p.RefreshQuota(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a, _ := m.GetByID("a"); a.Quota.Signals["X-Codex-Primary-Used-Percent"] != "98" {
		t.Fatalf("observation not recorded: %+v", a.Quota)
	}
}

func TestQuotaPollPanicInProbeBecomesAFailedPoll(t *testing.T) {
	f := newPollFixture(t, oauthAuth("a", "codex", time.Now().Add(time.Hour)))
	f.probe.result = func(pollProbeCall) (map[string]string, error) { panic("probe bug") }
	results := f.refresh(t)
	if results[0].Error != "poll failed unexpectedly" {
		t.Fatalf("panic leaked: %+v", results)
	}
	if entry := f.account(t, "a"); entry.QuotaStopped || entry.LastPollError != "poll failed unexpectedly" {
		t.Fatalf("account after panic: %+v", entry)
	}
	// The slot is free again: a later poll works.
	f.clock.Advance(time.Minute)
	f.probe.result = func(pollProbeCall) (map[string]string, error) { return codexPoll(50, 50), nil }
	if r := f.refresh(t); r[0].Error != "" {
		t.Fatalf("poller wedged after a panic: %+v", r)
	}
}

func TestQuotaPollerRefreshesAnAboutToExpireTokenFirst(t *testing.T) {
	a := oauthAuth("a", "codex", time.Now().Add(10*time.Second))
	a.Metadata["refresh_token"] = "refresh-a"
	f := newPollFixture(t, a)
	exec := &pollRefreshExecutor{}
	f.manager.RegisterExecutor(exec)
	f.refresh(t)
	if exec.refreshed.Load() != 1 || f.probe.calls[0].token != "tok-refreshed" {
		t.Fatalf("refreshed=%d token=%q", exec.refreshed.Load(), f.probe.calls[0].token)
	}
}
