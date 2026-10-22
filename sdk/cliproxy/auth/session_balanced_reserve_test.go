package auth

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// remainingObservation builds a snapshot whose short and long windows have the
// given remaining percentages, in each provider's native signal units.
func remainingObservation(now time.Time, provider string, shortRemaining, longRemaining float64) QuotaState {
	format := func(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }
	if provider == "claude" {
		return QuotaState{ObservedAt: now, Signals: map[string]string{
			"anthropic-ratelimit-unified-5h-utilization": format((100 - shortRemaining) / 100),
			"anthropic-ratelimit-unified-7d-utilization": format((100 - longRemaining) / 100),
		}}
	}
	return QuotaState{ObservedAt: now, Signals: map[string]string{
		"x-codex-primary-used-percent":   format(100 - shortRemaining),
		"x-codex-secondary-used-percent": format(100 - longRemaining),
	}}
}

type reserveFixture struct {
	s    *SessionBalancedSelector
	pool []*Auth
	now  *time.Time
}

func newReserveFixture(t *testing.T, provider, path string) *reserveFixture {
	t.Helper()
	now := time.Now()
	f := &reserveFixture{s: NewSessionBalancedSelector(path, time.Hour), pool: balancedPool(), now: &now}
	t.Cleanup(f.s.Stop)
	f.s.now = func() time.Time { return *f.now }
	for _, a := range f.pool {
		a.Provider = provider
	}
	// a is the preferred account for every new conversation.
	f.pool[0].Attributes = map[string]string{"priority": "10"}
	f.s.accounts = func() []*Auth { return f.pool }
	return f
}

func (f *reserveFixture) account(t *testing.T, id string) RoutingAccount {
	t.Helper()
	for _, a := range f.s.Snapshot().Accounts {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("account %s missing from snapshot", id)
	return RoutingAccount{}
}

func TestSessionQuotaPerWindowReservesWithDefaults(t *testing.T) {
	for _, provider := range []string{"claude", "codex"} {
		for _, tc := range []struct {
			name        string
			short, long float64
			want        string
		}{
			{"short 4% stops", 4, 50, "5-hour window at 4% remaining (reserve 5%)"},
			{"short at the reserve stops", 5, 50, "5-hour window at 5% remaining (reserve 5%)"},
			{"short just above the reserve runs", 5.01, 50, ""},
			{"short fractional reason", 3.5, 50, "5-hour window at 3.5% remaining (reserve 5%)"},
			{"long 3% runs", 50, 3, ""},
			{"long just above the reserve runs", 50, 2.01, ""},
			{"long at the reserve stops", 50, 2, "weekly window at 2% remaining (reserve 2%)"},
			{"long 1% stops", 50, 1, "weekly window at 1% remaining (reserve 2%)"},
			{"both windows stop", 3, 1, "5-hour window at 3% remaining (reserve 5%); weekly window at 1% remaining (reserve 2%)"},
			{"exhausted", 0, 0, "5-hour window at 0% remaining (reserve 5%); weekly window at 0% remaining (reserve 2%)"},
		} {
			t.Run(provider+"/"+tc.name, func(t *testing.T) {
				f := newReserveFixture(t, provider, "")
				balancedPick(t, f.s, balancedOptions("caller", "session"), f.pool)
				f.pool[0].Quota = remainingObservation(*f.now, provider, tc.short, tc.long)
				got := balancedPick(t, f.s, balancedOptions("caller", "session"), f.pool)
				entry := f.account(t, "a")
				if want := tc.want != ""; entry.QuotaStopped != want || entry.QuotaStopReason != tc.want {
					t.Fatalf("stopped=%v reason=%q, want reason %q", entry.QuotaStopped, entry.QuotaStopReason, tc.want)
				}
				row := f.s.Snapshot().Sessions[0]
				if tc.want == "" {
					if got.ID != "a" || row.Generation != 1 {
						t.Fatalf("healthy account lost the conversation: %s %+v", got.ID, row)
					}
					return
				}
				if got.ID != "b" || row.Generation != 2 || len(row.Migrations) != 1 || row.Migrations[0].Reason != tc.want || row.Reason != tc.want {
					t.Fatalf("stopped account kept the conversation: %s %+v", got.ID, row)
				}
			})
		}
	}
}

func TestSessionQuotaStopSetsPendingReasonOnPinnedBinding(t *testing.T) {
	f := newReserveFixture(t, "codex", "")
	balancedPick(t, f.s, balancedOptions("caller", "pinned"), f.pool)
	f.pool[0].Quota = remainingObservation(*f.now, "codex", 4, 50)
	// Only the reserve-stopped account is offered: the reserve is spent rather
	// than failing the conversation, and nothing is marked to move.
	got, err := f.s.Pick(context.Background(), "codex", "model", balancedOptions("caller", "pinned"), f.pool[:1])
	if err != nil || got.ID != "a" {
		t.Fatalf("reserve-only stop without alternatives must keep serving: %v %v", got, err)
	}
	row := f.s.Snapshot().Sessions[0]
	if row.AuthID != "a" || row.PendingReason != "" || row.Generation != 1 {
		t.Fatalf("binding changed without an alternative: %+v", row)
	}
	// An exhausted window is provider-enforced: no alternative is an error that keeps ownership.
	*f.now = f.now.Add(time.Second)
	f.pool[0].Quota = remainingObservation(*f.now, "codex", 0, 50)
	if _, err := f.s.Pick(context.Background(), "codex", "model", balancedOptions("caller", "pinned"), f.pool[:1]); statusCodeFromError(err) != 503 {
		t.Fatalf("exhausted account without replacement must be an error: %v", err)
	}
	row = f.s.Snapshot().Sessions[0]
	const want = "5-hour window at 0% remaining (reserve 5%)"
	if row.AuthID != "a" || row.PendingReason != want || row.Generation != 1 {
		t.Fatalf("pinned binding was not marked pending: %+v", row)
	}
	if got := balancedPick(t, f.s, balancedOptions("caller", "pinned"), f.pool); got.ID != "b" {
		t.Fatalf("pending binding did not migrate on the next safe request: %s", got.ID)
	}
}

func TestSessionQuotaReserveChangeTakesEffectWithoutRestart(t *testing.T) {
	f := newReserveFixture(t, "codex", "")
	f.s.SetQuotaReserves(SessionQuotaReserves{Short: 2, Long: 2})
	f.pool[0].Quota = remainingObservation(*f.now, "codex", 4, 50)
	if got := balancedPick(t, f.s, balancedOptions("caller", "session"), f.pool); got.ID != "a" {
		t.Fatalf("4%% remaining must run under a 2%% reserve, got %s", got.ID)
	}
	// Raising the reserve stops the account at once, before any request arrives.
	f.s.SetQuotaReserves(SessionQuotaReserves{Short: 5, Long: 2})
	const want = "5-hour window at 4% remaining (reserve 5%)"
	if entry := f.account(t, "a"); !entry.QuotaStopped || entry.QuotaStopReason != want {
		t.Fatalf("raised reserve not applied: %+v", entry)
	}
	if got := balancedPick(t, f.s, balancedOptions("caller", "session"), f.pool); got.ID != "b" {
		t.Fatalf("raised reserve did not migrate the conversation: %s", got.ID)
	}
	if got := balancedPick(t, f.s, balancedOptions("caller", "new"), f.pool); got.ID != "b" {
		t.Fatalf("raised reserve still admitted a new conversation: %s", got.ID)
	}

	// Lowering it alone releases nothing: the same stale-or-equal observation
	// cannot prove recovery.
	f.s.SetQuotaReserves(SessionQuotaReserves{Short: 2, Long: 2})
	if entry := f.account(t, "a"); !entry.QuotaStopped {
		t.Fatal("lowering the reserve released the stop without a new observation")
	}
	// A newer fresh observation above the lowered reserve releases it, and the
	// migrated conversation is not moved back.
	*f.now = f.now.Add(time.Minute)
	f.pool[0].Quota = remainingObservation(*f.now, "codex", 4, 50)
	if entry := f.account(t, "a"); entry.QuotaStopped {
		t.Fatalf("fresh observation above the lowered reserve did not release the stop: %+v", entry)
	}
	if got := balancedPick(t, f.s, balancedOptions("caller", "session"), f.pool); got.ID != "b" {
		t.Fatal("recovery moved the conversation back")
	}
	if got := balancedPick(t, f.s, balancedOptions("caller", "after-recovery"), f.pool); got.ID != "a" {
		t.Fatalf("released account was not eligible for new conversations: %s", got.ID)
	}
}

func TestSessionQuotaReserveChangeKeepsOnlyWhatTheObservationSupports(t *testing.T) {
	f := newReserveFixture(t, "codex", "")
	f.s.SetQuotaReserves(SessionQuotaReserves{Short: 5, Long: 2})
	f.pool[0].Quota = remainingObservation(*f.now, "codex", 4, 1.5)
	balancedPick(t, f.s, balancedOptions("caller", "session"), f.pool)
	if reason := f.account(t, "a").QuotaStopReason; !strings.Contains(reason, "5-hour") || !strings.Contains(reason, "weekly") {
		t.Fatalf("both windows should be stopped: %q", reason)
	}
	// Only the long reserve drops below the observation: the short stop stays.
	f.s.SetQuotaReserves(SessionQuotaReserves{Short: 5, Long: 1})
	*f.now = f.now.Add(time.Minute)
	f.pool[0].Quota = remainingObservation(*f.now, "codex", 4, 1.5)
	if reason := f.account(t, "a").QuotaStopReason; reason != "5-hour window at 4% remaining (reserve 5%)" {
		t.Fatalf("long window should have been released alone: %q", reason)
	}
	// A reserve edit refreshes the wording of a stop that stays valid.
	f.s.SetQuotaReserves(SessionQuotaReserves{Short: 10, Long: 1})
	if reason := f.account(t, "a").QuotaStopReason; reason != "5-hour window at 4% remaining (reserve 10%)" {
		t.Fatalf("stop wording not refreshed: %q", reason)
	}
}

func TestSessionQuotaRecoveryNeedsFreshNewerObservationAboveThatWindowReserve(t *testing.T) {
	f := newReserveFixture(t, "codex", "")
	f.pool[0].Quota = remainingObservation(*f.now, "codex", 3, 1)
	balancedPick(t, f.s, balancedOptions("caller", "low"), f.pool)
	stopped := func() string { return f.account(t, "a").QuotaStopReason }
	if got := stopped(); !strings.Contains(got, "5-hour") || !strings.Contains(got, "weekly") {
		t.Fatalf("setup: %q", got)
	}
	// Recovered short window, long window missing: the long stop must survive.
	*f.now = f.now.Add(time.Minute)
	f.pool[0].Quota = QuotaState{ObservedAt: *f.now, Signals: map[string]string{"x-codex-primary-used-percent": "10"}}
	if got := stopped(); got != "weekly window at 1% remaining (reserve 2%)" {
		t.Fatalf("missing window cleared another window's stop or kept the wrong one: %q", got)
	}
	// Long window recovered to 2.5% is above its 2% reserve but below the short one: it recovers.
	*f.now = f.now.Add(time.Minute)
	f.pool[0].Quota = remainingObservation(*f.now, "codex", 90, 2.5)
	if got := stopped(); got != "" {
		t.Fatalf("2.5%% remaining must clear a 2%% long reserve: %q", got)
	}
	// A recovery observation that is no longer fresh when evaluated never clears.
	f.pool[0].Quota = remainingObservation(*f.now, "codex", 3, 50)
	if got := stopped(); !strings.Contains(got, "5-hour") {
		t.Fatalf("setup 2: %q", got)
	}
	*f.now = f.now.Add(time.Hour)
	f.pool[0].Quota = remainingObservation(f.now.Add(-10*time.Minute), "codex", 90, 90)
	if got := stopped(); !strings.Contains(got, "5-hour") {
		t.Fatalf("an observation older than five minutes released a stop: %q", got)
	}
	// Until the window resets.
	f.pool[0].Quota = remainingObservation(*f.now, "codex", 3, 50)
	f.pool[0].Quota.Signals["x-codex-primary-reset-at"] = strconv.FormatInt(f.now.Add(time.Hour).Unix(), 10)
	if got := stopped(); got == "" {
		t.Fatal("setup 3: expected a stop")
	}
	*f.now = f.now.Add(2 * time.Hour)
	f.pool[0].Quota = QuotaState{}
	if got := stopped(); got != "" {
		t.Fatalf("reset did not release the stop: %q", got)
	}
}

func TestSessionQuotaFractionBoundaryIsStable(t *testing.T) {
	// Claude reports a 0..1 fraction. Converting it to a percent must not let
	// floating point noise move an account across its reserve: with a reserve of
	// k%, a window with exactly k% remaining is stopped and k+0.01% is not.
	for k := 1; k <= 50; k++ {
		f := newReserveFixture(t, "claude", "")
		f.s.SetQuotaReserves(SessionQuotaReserves{Short: float64(k), Long: float64(k)})
		observe := func(remaining float64) bool {
			utilization := strconv.FormatFloat((100-remaining)/100, 'f', -1, 64)
			f.pool[0].Quota = QuotaState{ObservedAt: *f.now, Signals: map[string]string{"anthropic-ratelimit-unified-5h-utilization": utilization}}
			return f.account(t, "a").QuotaStopped
		}
		if !observe(float64(k)) {
			t.Fatalf("reserve %d%%: exactly %d%% remaining was not stopped", k, k)
		}
		*f.now = f.now.Add(time.Minute)
		if observe(float64(k) + 0.01) {
			t.Fatalf("reserve %d%%: %.2f%% remaining stayed stopped", k, float64(k)+0.01)
		}
	}
}

func TestSessionQuotaPersistedStopsSurviveReserveChangeAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	f := newReserveFixture(t, "codex", path)
	f.pool[0].Quota = remainingObservation(*f.now, "codex", 4, 50)
	if got := balancedPick(t, f.s, balancedOptions("caller", "one"), f.pool); got.ID != "b" {
		t.Fatalf("setup: stopped account selected: %s", got.ID)
	}
	f.s.Stop()

	// Restart with a lower reserve: a 4% stop recorded under a 5% reserve is now
	// above the reserve, yet it must load (not fail the state closed) and hold
	// until a newer observation confirms recovery.
	restarted := NewSessionBalancedSelector(path, time.Hour)
	t.Cleanup(restarted.Stop)
	restarted.SetQuotaReserves(SessionQuotaReserves{Short: 2, Long: 2})
	restarted.now = func() time.Time { return *f.now }
	restarted.accounts = func() []*Auth { return f.pool }
	f.pool[0].Quota = QuotaState{}
	if got := balancedPick(t, restarted, balancedOptions("caller", "two"), f.pool); got.ID != "b" {
		t.Fatalf("persisted stop was lost across restart: %s", got.ID)
	}
	*f.now = f.now.Add(time.Minute)
	f.pool[0].Quota = remainingObservation(*f.now, "codex", 4, 50)
	if got := balancedPick(t, restarted, balancedOptions("caller", "three"), f.pool); got.ID != "a" {
		t.Fatalf("fresh observation above the lowered reserve did not release the stop: %s", got.ID)
	}
}

func TestSessionQuotaLegacyPersistedStopLoadsAndIsReworded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	now := time.Now()
	const key = "x-codex-primary-used-percent"
	writer := NewSessionBalancedSelector(path, time.Hour)
	writer.state.QuotaStops = map[string]map[string]sessionQuotaStop{"a": {key: {RemainingPercent: 1, ObservedAt: now, Reason: "quota reserve reached (1% remaining or less)"}}}
	if err := writer.persist(); err != nil {
		t.Fatal(err)
	}
	writer.Stop()

	f := newReserveFixture(t, "codex", path)
	f.s.now = func() time.Time { return now }
	f.pool[0].Quota = remainingObservation(now, "codex", 1, 50)
	if got := balancedPick(t, f.s, balancedOptions("caller", "legacy"), f.pool); got.ID != "b" {
		t.Fatalf("legacy stop ignored: %s", got.ID)
	}
	stop := f.s.state.QuotaStops["a"][key]
	if stop.Reason != "5-hour window at 1% remaining (reserve 5%)" || !stop.ObservedAt.Equal(now) {
		t.Fatalf("legacy stop not reworded in place: %+v", stop)
	}

	for _, remaining := range []float64{-1, 101} {
		bad := NewSessionBalancedSelector(filepath.Join(t.TempDir(), "state"), time.Hour)
		bad.state.QuotaStops = map[string]map[string]sessionQuotaStop{"a": {key: {RemainingPercent: remaining, ObservedAt: now, Reason: "x"}}}
		if err := bad.persist(); err != nil {
			t.Fatal(err)
		}
		bad.Stop()
		restored := NewSessionBalancedSelector(bad.path, time.Hour)
		if _, err := restored.Pick(context.Background(), "codex", "model", balancedOptions("caller", "bad"), balancedPool()); statusCodeFromError(err) != 503 {
			t.Fatalf("remaining %v accepted: %v", remaining, err)
		}
		restored.Stop()
	}
}

func TestSessionQuotaWindowLabelsFollowWindowLength(t *testing.T) {
	for _, tc := range []struct {
		minutes, label string
	}{{"10080", "weekly"}, {"43200", "monthly"}, {"40320", "monthly"}, {"44640", "monthly"}, {"", "weekly"}, {"20160", "weekly"}} {
		f := newReserveFixture(t, "codex", "")
		f.pool[0].Quota = remainingObservation(*f.now, "codex", 50, 1)
		if tc.minutes != "" {
			f.pool[0].Quota.Signals["x-codex-secondary-window-minutes"] = tc.minutes
		}
		f.s.RefreshQuotaStops()
		want := tc.label + " window at 1% remaining (reserve 2%)"
		if got := f.account(t, "a").QuotaStopReason; got != want {
			t.Fatalf("window minutes %q: %q, want %q", tc.minutes, got, want)
		}
	}
}

type fakePollInfo struct {
	interval time.Duration
	status   map[string]QuotaPollStatus
}

func (f fakePollInfo) QuotaPollInterval() time.Duration { return f.interval }
func (f fakePollInfo) QuotaPollStatus(id string) QuotaPollStatus {
	return f.status[id]
}

func TestRoutingSnapshotExposesWindowsReservesAndPollStatus(t *testing.T) {
	f := newReserveFixture(t, "claude", "")
	shortReset := f.now.Add(2 * time.Hour).Truncate(time.Second)
	f.pool = append(f.pool, &Auth{ID: "g", Provider: "gemini"}, &Auth{ID: "n", Provider: "codex"})
	f.pool[0].Quota = remainingObservation(*f.now, "claude", 3, 80)
	f.pool[0].Quota.Signals["anthropic-ratelimit-unified-5h-reset"] = strconv.FormatInt(shortReset.Unix(), 10)
	polledAt := f.now.Add(-30 * time.Second).UTC().Truncate(time.Second)
	f.s.pollInfo = fakePollInfo{interval: 5 * time.Minute, status: map[string]QuotaPollStatus{
		"a": {LastPollAt: polledAt, LastSuccessAt: polledAt},
		"b": {LastPollAt: polledAt, LastError: "HTTP 401"},
	}}
	f.s.SetQuotaReserves(SessionQuotaReserves{Short: 5, Long: 2})

	raw, err := json.Marshal(f.s.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Enabled                   bool             `json:"enabled"`
		QuotaPollIntervalSeconds  int              `json:"quota_poll_interval_seconds"`
		ShortWindowReservePercent float64          `json:"short_window_reserve_percent"`
		LongWindowReservePercent  float64          `json:"long_window_reserve_percent"`
		Accounts                  []map[string]any `json:"accounts"`
	}
	if err = json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.Enabled || decoded.QuotaPollIntervalSeconds != 300 || decoded.ShortWindowReservePercent != 5 || decoded.LongWindowReservePercent != 2 {
		t.Fatalf("top level: %s", raw)
	}
	byID := map[string]map[string]any{}
	for _, a := range decoded.Accounts {
		byID[a["id"].(string)] = a
	}
	var keys []string
	for k := range byID["a"] {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	wantKeys := []string{"disabled", "draining", "id", "label", "last_poll_at", "last_poll_error", "last_poll_success_at", "observed_at", "provider", "quota_exhausted", "quota_stop_reason", "quota_stopped", "recent_sessions", "remaining_percent", "windows"}
	if !reflect.DeepEqual(keys, wantKeys) {
		t.Fatalf("account keys = %v, want %v", keys, wantKeys)
	}
	a := byID["a"]
	if a["last_poll_at"] != polledAt.Format(time.RFC3339) || a["last_poll_success_at"] != polledAt.Format(time.RFC3339) || a["last_poll_error"] != "" {
		t.Fatalf("poll status: %v", a)
	}
	wantWindows := []any{
		map[string]any{"kind": "short", "label": "5-hour", "remaining_percent": 3.0, "reset_at": shortReset.UTC().Format(time.RFC3339), "reserve_percent": 5.0, "stopped": true},
		map[string]any{"kind": "long", "label": "weekly", "remaining_percent": 80.0, "reset_at": "", "reserve_percent": 2.0, "stopped": false},
	}
	if !reflect.DeepEqual(a["windows"], wantWindows) {
		t.Fatalf("windows = %#v\nwant %#v", a["windows"], wantWindows)
	}
	if b := byID["b"]; b["last_poll_at"] != polledAt.Format(time.RFC3339) || b["last_poll_success_at"] != "" || b["last_poll_error"] != "HTTP 401" {
		t.Fatalf("failed poll status: %v", b)
	}
	// An unobserved account lists its windows with unknown remaining; other providers list none.
	n := byID["n"]
	if windows, _ := n["windows"].([]any); len(windows) != 2 || windows[0].(map[string]any)["remaining_percent"] != nil || n["last_poll_at"] != "" {
		t.Fatalf("unobserved account: %v", n)
	}
	if windows, ok := byID["g"]["windows"].([]any); !ok || len(windows) != 0 {
		t.Fatalf("non-quota provider windows must be an empty list: %s", raw)
	}
}

func TestRoutingSnapshotWindowRemainingIsNullWhenStaleButKeepsReset(t *testing.T) {
	f := newReserveFixture(t, "codex", "")
	reset := f.now.Add(3 * time.Hour).Truncate(time.Second)
	f.pool[0].Quota = remainingObservation(f.now.Add(-6*time.Minute), "codex", 40, 40)
	f.pool[0].Quota.Signals["x-codex-primary-reset-at"] = strconv.FormatInt(reset.Unix(), 10)
	windows := f.account(t, "a").Windows
	if windows[0].RemainingPercent != nil || windows[1].RemainingPercent != nil {
		t.Fatalf("stale remaining must be null: %+v", windows)
	}
	if windows[0].ResetAt != reset.UTC().Format(time.RFC3339) {
		t.Fatalf("reset instant should outlive the utilization freshness: %+v", windows[0])
	}
	// A window whose reset has passed has no meaningful remaining value either.
	f.pool[0].Quota = remainingObservation(*f.now, "codex", 40, 40)
	f.pool[0].Quota.Signals["x-codex-primary-reset-at"] = strconv.FormatInt(f.now.Add(-time.Minute).Unix(), 10)
	if got := f.account(t, "a").Windows[0]; got.RemainingPercent != nil || got.ResetAt != "" {
		t.Fatalf("expired window: %+v", got)
	}
}

func TestSessionQuotaReservesNormalize(t *testing.T) {
	s := NewSessionBalancedSelector("", time.Hour)
	defer s.Stop()
	if got := s.QuotaReserves(); got != (SessionQuotaReserves{Short: 5, Long: 2}) {
		t.Fatalf("defaults = %+v", got)
	}
	s.SetQuotaReserves(SessionQuotaReserves{Short: -1, Long: 250})
	if got := s.QuotaReserves(); got != (SessionQuotaReserves{Short: 5, Long: 2}) {
		t.Fatalf("invalid reserves must fall back to the defaults, got %+v", got)
	}
	s.SetQuotaReserves(SessionQuotaReserves{Short: 0, Long: 50})
	if got := s.QuotaReserves(); got != (SessionQuotaReserves{Short: 0, Long: 50}) {
		t.Fatalf("explicit zero lost: %+v", got)
	}
}

func TestSessionQuotaCodexWindowLengthOverridesPosition(t *testing.T) {
	// A plan with only a weekly window reports it as "primary". Judged by
	// position it would be a short window with a 5% reserve; its stated length
	// makes it a long window with the 2% reserve.
	weeklyPrimary := func(f *reserveFixture, used string) {
		f.pool[0].Quota = QuotaState{ObservedAt: *f.now, Signals: map[string]string{
			"x-codex-primary-used-percent":   used,
			"x-codex-primary-window-minutes": "10080",
		}}
	}
	f := newReserveFixture(t, "codex", "")
	weeklyPrimary(f, "97") // 3% remaining
	entry := f.account(t, "a")
	if entry.QuotaStopped {
		t.Fatalf("3%% of a weekly window stopped the account under the 2%% long reserve: %+v", entry)
	}
	if len(entry.Windows) != 1 || entry.Windows[0].Kind != "long" || entry.Windows[0].Label != "weekly" || entry.Windows[0].ReservePercent != 2 || *entry.Windows[0].RemainingPercent != 3 {
		t.Fatalf("windows: %+v", entry.Windows)
	}
	*f.now = f.now.Add(time.Minute)
	weeklyPrimary(f, "98")
	if entry = f.account(t, "a"); entry.QuotaStopReason != "weekly window at 2% remaining (reserve 2%)" || !entry.Windows[0].Stopped {
		t.Fatalf("weekly window at the reserve not stopped: %+v", entry)
	}

	// A five-hour primary window stays short.
	short := newReserveFixture(t, "codex", "")
	short.pool[0].Quota = QuotaState{ObservedAt: *short.now, Signals: map[string]string{"x-codex-primary-used-percent": "97", "x-codex-primary-window-minutes": "300"}}
	if entry = short.account(t, "a"); entry.QuotaStopReason != "5-hour window at 3% remaining (reserve 5%)" || entry.Windows[0].Kind != "short" {
		t.Fatalf("5-hour window: %+v", entry)
	}
	// Without a stated length, position decides (response headers rarely omit it, the original behaviour).
	positional := newReserveFixture(t, "codex", "")
	positional.pool[0].Quota = QuotaState{ObservedAt: *positional.now, Signals: map[string]string{"x-codex-primary-used-percent": "97"}}
	if entry = positional.account(t, "a"); entry.QuotaStopReason != "5-hour window at 3% remaining (reserve 5%)" {
		t.Fatalf("positional fallback: %+v", entry)
	}
}

func TestRoutingSnapshotKeepsStoppedWindowAbsentFromLatestSnapshot(t *testing.T) {
	f := newReserveFixture(t, "claude", "")
	f.pool[0].Quota = remainingObservation(*f.now, "claude", 50, 1)
	if !f.account(t, "a").Windows[1].Stopped {
		t.Fatal("setup: weekly window not stopped")
	}
	// A later partial snapshot omits the weekly window; its stop survives and stays visible.
	*f.now = f.now.Add(time.Minute)
	f.pool[0].Quota = QuotaState{ObservedAt: *f.now, Signals: map[string]string{"anthropic-ratelimit-unified-5h-utilization": "0.5"}}
	windows := f.account(t, "a").Windows
	if len(windows) != 2 || windows[0].Kind != "short" || windows[1].Kind != "long" || !windows[1].Stopped || windows[1].RemainingPercent != nil || windows[1].Label != "weekly" {
		t.Fatalf("windows: %+v", windows)
	}
}

func TestSessionReserveMovesOnlyWhenRoomExists(t *testing.T) {
	f := newReserveFixture(t, "codex", "")
	balancedPick(t, f.s, balancedOptions("caller", "pinned"), f.pool)
	// Both accounts inside their reserve: the conversation stays and keeps its cache.
	f.pool[0].Quota = remainingObservation(*f.now, "codex", 4, 50)
	f.pool[1].Quota = remainingObservation(*f.now, "codex", 3, 50)
	if got := balancedPick(t, f.s, balancedOptions("caller", "pinned"), f.pool); got.ID != "a" {
		t.Fatalf("all-in-reserve conversation moved: %s", got.ID)
	}
	if row := f.s.Snapshot().Sessions[0]; row.PendingReason != "" || row.Generation != 1 {
		t.Fatalf("all-in-reserve conversation marked to move: %+v", row)
	}
	// A new conversation still gets the account with the most room.
	if got := balancedPick(t, f.s, balancedOptions("caller", "fresh"), f.pool); got.ID != "a" {
		t.Fatalf("new conversation did not take the roomier reserve account: %s", got.ID)
	}
	// Once b recovers above its reserve, the conversation on a moves.
	f.pool[1].Quota = remainingObservation(f.now.Add(time.Second), "codex", 60, 50)
	*f.now = f.now.Add(time.Second)
	if got := balancedPick(t, f.s, balancedOptions("caller", "pinned"), f.pool); got.ID != "b" {
		t.Fatalf("conversation did not move once room appeared: %s", got.ID)
	}
	entry := f.account(t, "a")
	if !entry.QuotaStopped || entry.QuotaExhausted {
		t.Fatalf("reserve stop flags: %+v", entry)
	}
}

func TestSessionQuotaPendingMoveClearsAfterVerifiedRecovery(t *testing.T) {
	f := newReserveFixture(t, "codex", "")
	balancedPick(t, f.s, balancedOptions("caller", "quota"), f.pool)
	balancedPick(t, f.s, balancedOptions("caller", "manual"), f.pool)
	markPending := func() {
		f.s.mu.Lock()
		defer f.s.mu.Unlock()
		for _, b := range f.s.state.Sessions {
			if b.AuthID != "a" {
				t.Fatalf("fixture placed a session on %s", b.AuthID)
			}
			b.PendingReason = "5-hour window at 0% remaining (reserve 5%)"
			if strings.HasSuffix(b.SessionID, "manual") {
				b.PendingReason = "manual move"
			}
		}
		delete(f.s.state.QuotaStops, "a")
	}
	markPending()
	// No stop is recorded, but a stale observation is not evidence of recovery.
	f.pool[0].Quota = remainingObservation(f.now.Add(-10*time.Minute), "codex", 60, 50)
	for _, row := range f.s.Snapshot().Sessions {
		if row.PendingReason == "" {
			t.Fatalf("stale observation cleared a pending move: %+v", row)
		}
	}
	f.pool[0].Quota = remainingObservation(*f.now, "codex", 60, 50)
	sawManual := false
	for _, row := range f.s.Snapshot().Sessions {
		want := ""
		if strings.HasSuffix(row.SessionID, "manual") {
			want, sawManual = "manual move", true
		}
		if row.PendingReason != want {
			t.Fatalf("pending after recovery = %q, want %q (%s)", row.PendingReason, want, row.SessionID)
		}
	}
	if !sawManual {
		t.Fatal("fixture lost the manual session")
	}
	if got := balancedPick(t, f.s, balancedOptions("caller", "quota"), f.pool); got.ID != "a" {
		t.Fatalf("recovered conversation moved anyway: %s", got.ID)
	}
}
