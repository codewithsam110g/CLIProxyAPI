package auth

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// SessionQuotaReserves are the remaining-percent thresholds at or below which a
// shared quota window stops its account. The short window is the Claude 5-hour /
// Codex primary window; the long window is the Claude 7-day / Codex secondary one.
type SessionQuotaReserves struct {
	Short float64
	Long  float64
}

// DefaultSessionQuotaReserves returns the reserves used until configuration is applied.
func DefaultSessionQuotaReserves() SessionQuotaReserves {
	return SessionQuotaReserves{
		Short: internalconfig.DefaultSessionQuotaShortReservePercent,
		Long:  internalconfig.DefaultSessionQuotaLongReservePercent,
	}
}

func (r SessionQuotaReserves) normalized() SessionQuotaReserves {
	fix := func(v, fallback float64) float64 {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 100 {
			return fallback
		}
		return v
	}
	d := DefaultSessionQuotaReserves()
	return SessionQuotaReserves{Short: fix(r.Short, d.Short), Long: fix(r.Long, d.Long)}
}

// quotaWindowSpec describes one shared quota window the router tracks. The
// observation keys are the passive header names; the usage poller emits the same.
type quotaWindowSpec struct {
	provider string
	key      string // utilization / used-percent signal
	reset    string // reset signal
	fraction bool   // key is a 0..1 fraction instead of a percent
	long     bool
}

var quotaWindowSpecs = []quotaWindowSpec{
	{"claude", "anthropic-ratelimit-unified-5h-utilization", "anthropic-ratelimit-unified-5h-reset", true, false},
	{"claude", "anthropic-ratelimit-unified-7d-utilization", "anthropic-ratelimit-unified-7d-reset", true, true},
	{"codex", "x-codex-primary-used-percent", "x-codex-primary-reset-at", false, false},
	{"codex", "x-codex-secondary-used-percent", "x-codex-secondary-reset-at", false, true},
}

func quotaWindowSpecFor(key string) (quotaWindowSpec, bool) {
	for _, spec := range quotaWindowSpecs {
		if spec.key == key {
			return spec, true
		}
	}
	return quotaWindowSpec{}, false
}

// Quota stops outlive the short scoring snapshot. A missing observation cannot
// make a stopped account usable again; its window must reset or report recovery.
//
// Window and ReservePercent describe the reserve the stop was evaluated against.
// They are informational: validity and recovery never depend on the reserve that
// is configured when the state is loaded, so changing the reserve can neither
// invalidate the state file nor strand an account.
type sessionQuotaStop struct {
	RemainingPercent float64   `json:"remaining_percent"`
	ObservedAt       time.Time `json:"observed_at"`
	ResetAt          time.Time `json:"reset_at,omitempty"`
	Reason           string    `json:"reason"`
	Window           string    `json:"window,omitempty"`
	ReservePercent   float64   `json:"reserve_percent,omitempty"`
	// Long is derived from the current observation (never persisted): whether the
	// window is a long one, which selects the reserve.
	Long bool `json:"-"`
}

func validSessionQuotaStop(name string, stop sessionQuotaStop) bool {
	if name != "confirmed" {
		if _, ok := quotaWindowSpecFor(name); !ok {
			return false
		}
	}
	// Reserves are configurable, so the remaining percent a stop was recorded at
	// is only bounded by the percentage range, not by today's reserve.
	return !stop.ObservedAt.IsZero() && stop.Reason != "" &&
		stop.RemainingPercent >= 0 && stop.RemainingPercent <= 100 &&
		stop.ReservePercent >= 0 && stop.ReservePercent <= 100
}

func sessionReconnectRequired() error {
	return routingError("session_reconnect_required", "account migration requires a new connection and a full conversation replay", 409)
}

// IsSessionReconnectRequired reports a session ownership change that requires
// a fresh transport and full history instead of retrying an upstream delta.
func IsSessionReconnectRequired(err error) bool {
	var policy *Error
	return errors.As(err, &policy) && policy.Code == "session_reconnect_required"
}

// roundPercent keeps fraction-to-percent conversions stable at reserve boundaries.
func roundPercent(v float64) float64 { return math.Round(v*1e6) / 1e6 }

// quotaWindowKind classifies a window as short or long and names it. The signal
// key fixes the class for Claude. Codex names its windows by position, but a plan
// can report a weekly window as "primary" with no secondary one, so when the
// window length is stated it decides: anything longer than a day is a long
// window. Without a stated length the position decides.
func quotaWindowKind(spec quotaWindowSpec, signals map[string]string) (long bool, label string) {
	long = spec.long
	minutes := int64(0)
	if spec.provider == "codex" {
		prefix := strings.TrimSuffix(spec.key, "-used-percent")
		if m, err := strconv.ParseInt(signals[prefix+"-window-minutes"], 10, 64); err == nil && m > 0 {
			minutes = m
			long = m > 24*60
		}
	}
	switch {
	case !long:
		return false, "5-hour"
	case minutes >= 28*24*60 && minutes <= 31*24*60:
		// Calling a monthly window weekly would make the stop reason wrong.
		return true, "monthly"
	default:
		return true, "weekly"
	}
}

func formatQuotaPercent(v float64) string {
	return strconv.FormatFloat(math.Round(v*10)/10, 'f', -1, 64)
}

func quotaStopReason(label string, remaining, reserve float64) string {
	return fmt.Sprintf("%s window at %s%% remaining (reserve %s%%)", label, formatQuotaPercent(remaining), formatQuotaPercent(reserve))
}

func (s *SessionBalancedSelector) reserve(long bool) float64 {
	if long {
		return s.reserves.Long
	}
	return s.reserves.Short
}

// quotaWindowObservations lists the shared windows present in the auth's
// current snapshot, keyed by the utilization signal. Reasons and reserves are
// attached when a stop is recorded, since they depend on selector configuration.
func quotaWindowObservations(a *Auth) map[string]sessionQuotaStop {
	windows := make(map[string]sessionQuotaStop)
	if a == nil {
		return windows
	}
	signals := make(map[string]string, len(a.Quota.Signals))
	for k, v := range a.Quota.Signals {
		signals[strings.ToLower(k)] = v
	}
	for _, spec := range quotaWindowSpecs {
		used, err := strconv.ParseFloat(signals[spec.key], 64)
		if err != nil || math.IsNaN(used) || math.IsInf(used, 0) || used < 0 {
			continue
		}
		if spec.fraction {
			used *= 100
		}
		reset := quotaResetTime(signals[spec.reset])
		if reset.IsZero() && strings.HasSuffix(spec.reset, "-reset-at") {
			if seconds, err := strconv.ParseInt(signals[strings.TrimSuffix(spec.reset, "-reset-at")+"-reset-after-seconds"], 10, 64); err == nil && seconds > 0 && seconds <= 366*24*60*60 {
				reset = a.Quota.ObservedAt.Add(time.Duration(seconds) * time.Second)
			}
		}
		long, label := quotaWindowKind(spec, signals)
		windows[spec.key] = sessionQuotaStop{RemainingPercent: math.Max(0, roundPercent(100-used)), ObservedAt: a.Quota.ObservedAt, ResetAt: reset, Window: label, Long: long}
	}
	return windows
}

func quotaResetTime(raw string) time.Time {
	if unix, err := strconv.ParseInt(raw, 10, 64); err == nil && unix > 0 {
		return time.Unix(unix, 0)
	}
	t, _ := time.Parse(time.RFC3339, raw)
	return t
}

// SetQuotaReserves applies new reserves without a restart. Raising a reserve
// stops accounts already inside it on the next evaluation, which runs here.
// Lowering one releases a stop only when a newer fresh observation confirms the
// window is above the lower reserve (see refreshQuotaStops).
func (s *SessionBalancedSelector) SetQuotaReserves(reserves SessionQuotaReserves) {
	reserves = reserves.normalized()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reserves == reserves {
		return
	}
	s.reserves = reserves
	if s.stopped || s.loadErr != nil {
		return
	}
	if s.refreshQuotaStops(nil, s.now()) {
		_ = s.persist() // A failed commit blocks subsequent selections via storeErr.
	}
}

// QuotaReserves returns the reserves currently enforced.
func (s *SessionBalancedSelector) QuotaReserves() SessionQuotaReserves {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reserves
}

// RefreshQuotaStops re-evaluates stops against the accounts' current
// observations, for callers (the usage poller) that learn quota out of band.
// Bound sessions still move only on their next safe request.
func (s *SessionBalancedSelector) RefreshQuotaStops() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped || s.loadErr != nil {
		return
	}
	if s.refreshQuotaStops(nil, s.now()) {
		_ = s.persist()
	}
}

// Caller holds s.mu. Manager snapshots include excluded accounts, so every
// conversation can recognize a confirmed account-wide quota failure.
func (s *SessionBalancedSelector) refreshQuotaStops(candidates []*Auth, now time.Time) bool {
	if s.state.QuotaStops == nil {
		s.state.QuotaStops = make(map[string]map[string]sessionQuotaStop)
	}
	changed := false
	recovered := make(map[string]bool)
	for id, windows := range s.state.QuotaStops {
		for name, stop := range windows {
			if !stop.ResetAt.IsZero() && !now.Before(stop.ResetAt) {
				delete(windows, name)
				changed = true
			}
		}
		if len(windows) == 0 {
			delete(s.state.QuotaStops, id)
		}
	}
	accounts := candidates
	if s.accounts != nil {
		accounts = s.accounts()
	}
	for _, a := range accounts {
		if a == nil {
			continue
		}
		windows := s.state.QuotaStops[a.ID]
		if windows == nil {
			windows = make(map[string]sessionQuotaStop)
		}
		credentialQuota := a.Quota.Exceeded && a.Quota.Reason == "credential_quota" && (a.Quota.NextRecoverAt.IsZero() || now.Before(a.Quota.NextRecoverAt))
		if credentialQuota {
			old, exists := windows["confirmed"]
			if !exists || (!old.ResetAt.IsZero() && a.Quota.NextRecoverAt.After(old.ResetAt)) {
				windows["confirmed"] = sessionQuotaStop{ObservedAt: now, ResetAt: a.Quota.NextRecoverAt, Reason: "confirmed credential quota"}
				changed = true
			}
		}
		observations := quotaWindowObservations(a)
		fresh := !a.Quota.ObservedAt.IsZero() && !a.Quota.ObservedAt.After(now.Add(time.Minute)) && now.Sub(a.Quota.ObservedAt) <= 5*time.Minute
		allHealthy := len(observations) >= 2
		for name, observation := range observations {
			if a.Quota.ObservedAt.IsZero() || a.Quota.ObservedAt.After(now.Add(time.Minute)) {
				continue
			}
			old, exists := windows[name]
			reserve := s.reserve(observation.Long)
			if observation.RemainingPercent <= reserve {
				allHealthy = false
				if !observation.ResetAt.IsZero() && !now.Before(observation.ResetAt) {
					continue
				}
				observation.ReservePercent = reserve
				observation.Reason = quotaStopReason(observation.Window, observation.RemainingPercent, reserve)
				if !exists || observation.ObservedAt.After(old.ObservedAt) {
					windows[name] = observation
					changed = true
				} else if old.ReservePercent != reserve || old.Window == "" {
					// The stop stays valid under the new reserve. Refresh its wording
					// but keep the original observation time: releasing it still
					// requires a newer observation, never a config edit alone.
					old.ReservePercent = reserve
					old.Window = observation.Window
					old.Reason = quotaStopReason(old.Window, old.RemainingPercent, reserve)
					windows[name] = old
					changed = true
				}
			} else if exists && fresh && observation.ObservedAt.After(old.ObservedAt) {
				delete(windows, name)
				changed = true
			}
		}
		if old, exists := windows["confirmed"]; exists && !credentialQuota && allHealthy && fresh && a.Quota.ObservedAt.After(old.ObservedAt) {
			delete(windows, "confirmed")
			changed = true
		}
		if len(windows) > 0 {
			s.state.QuotaStops[a.ID] = windows
		} else {
			delete(s.state.QuotaStops, a.ID)
			if fresh && allHealthy {
				recovered[a.ID] = true
			}
		}
	}
	// A move requested only because of quota is stale once the account has
	// verifiably recovered; moving then would discard the cache for nothing.
	for _, b := range s.state.Sessions {
		if b.PendingAuthID == "" && recovered[b.AuthID] && quotaPendingReason(b.PendingReason) {
			b.PendingReason = ""
			changed = true
		}
	}
	return changed
}

// quotaPendingReason reports a pending move caused by quota rather than by a
// manual request or an account failure.
func quotaPendingReason(reason string) bool {
	switch reason {
	case "", "manual move", "account unavailable", "account removed", "account disabled", "account authentication failed":
		return false
	}
	return true
}

func (s *SessionBalancedSelector) quotaStopReason(id string) string {
	windows := s.state.QuotaStops[id]
	if stop, ok := windows["confirmed"]; ok {
		return stop.Reason
	}
	var reasons []string
	for _, spec := range quotaWindowSpecs {
		if stop, ok := windows[spec.key]; ok && stop.Reason != "" {
			reasons = append(reasons, stop.Reason)
		}
	}
	if len(reasons) > 0 {
		return strings.Join(reasons, "; ")
	}
	if len(windows) > 0 {
		return "quota reserve reached"
	}
	return ""
}

// quotaExhausted reports a stop the provider will enforce: confirmed quota or a
// window with nothing left. Reserve-only stops are soft; an account inside its
// reserve keeps serving when no compatible account outside its reserve exists.
func (s *SessionBalancedSelector) quotaExhausted(id string) bool {
	for name, stop := range s.state.QuotaStops[id] {
		if name == "confirmed" || stop.RemainingPercent <= 0 {
			return true
		}
	}
	return false
}

// usableInReserve reports whether a quota-stopped account may still serve because
// the stop is reserve-only.
func (s *SessionBalancedSelector) usableInReserve(id string) bool {
	return s.quotaStopReason(id) != "" && !s.quotaExhausted(id)
}

func (s *SessionBalancedSelector) recordConfirmedQuotaStop(r Result) {
	if s.state.QuotaStops == nil {
		s.state.QuotaStops = make(map[string]map[string]sessionQuotaStop)
	}
	if s.state.QuotaStops[r.AuthID] == nil {
		s.state.QuotaStops[r.AuthID] = make(map[string]sessionQuotaStop)
	}
	var reset time.Time
	if r.RetryAfter != nil && *r.RetryAfter > 0 {
		reset = s.now().Add(*r.RetryAfter)
	}
	if a := s.account(r.AuthID); a != nil {
		for _, window := range quotaWindowObservations(a) {
			if window.RemainingPercent <= s.reserve(window.Long) && window.ResetAt.After(s.now()) && window.ResetAt.After(reset) {
				reset = window.ResetAt
			}
		}
	}
	if old := s.state.QuotaStops[r.AuthID]["confirmed"]; old.ResetAt.After(s.now()) && old.ResetAt.After(reset) {
		reset = old.ResetAt
	}
	s.state.QuotaStops[r.AuthID]["confirmed"] = sessionQuotaStop{ObservedAt: s.now(), ResetAt: reset, Reason: "confirmed quota exhaustion"}
}

// RoutingWindow is one shared quota window of an account as the router sees it.
type RoutingWindow struct {
	// Kind is "short" (Claude 5-hour, Codex primary) or "long" (Claude 7-day, Codex secondary).
	Kind string `json:"kind"`
	// Label is "5-hour", "weekly", or "monthly" for a Codex secondary window of that length.
	Label string `json:"label"`
	// RemainingPercent is null unless the account's snapshot is fresh (see accountHeadroom).
	RemainingPercent *float64 `json:"remaining_percent"`
	// ResetAt is RFC3339, or "" when unknown.
	ResetAt        string  `json:"reset_at"`
	ReservePercent float64 `json:"reserve_percent"`
	Stopped        bool    `json:"stopped"`
}

// accountWindows lists the windows present in the account's snapshot or held by
// a stop, short first. An account with neither lists both windows as unknown,
// unless it is an API-key credential.
// Caller holds s.mu.
func (s *SessionBalancedSelector) accountWindows(a *Auth, now time.Time) []RoutingWindow {
	out := []RoutingWindow{}
	provider := strings.ToLower(strings.TrimSpace(a.Provider))
	if provider != "claude" && provider != "codex" {
		return out
	}
	observations := quotaWindowObservations(a)
	fresh := !a.Quota.ObservedAt.IsZero() && now.Sub(a.Quota.ObservedAt) <= 5*time.Minute && !a.Quota.ObservedAt.After(now.Add(time.Minute))
	stops := s.state.QuotaStops[a.ID]
	for _, spec := range quotaWindowSpecs {
		if spec.provider != provider {
			continue
		}
		observation, observed := observations[spec.key]
		stop, stopped := stops[spec.key]
		if !observed && !stopped {
			continue
		}
		long, label := spec.long, ""
		switch {
		case observed:
			long, label = observation.Long, observation.Window
		case stop.Window != "":
			long, label = stop.Window != "5-hour", stop.Window
		default:
			_, label = quotaWindowKind(spec, nil)
		}
		window := RoutingWindow{Kind: "short", Label: label, ReservePercent: s.reserve(long), Stopped: stopped}
		if long {
			window.Kind = "long"
		}
		var resetAt time.Time
		if observed {
			if observation.ResetAt.After(now) {
				resetAt = observation.ResetAt
			}
			if fresh && (observation.ResetAt.IsZero() || now.Before(observation.ResetAt)) {
				remaining := observation.RemainingPercent
				window.RemainingPercent = &remaining
			}
		}
		if stopped && resetAt.IsZero() && stop.ResetAt.After(now) {
			resetAt = stop.ResetAt
		}
		if !resetAt.IsZero() {
			window.ResetAt = resetAt.UTC().Format(time.RFC3339)
		}
		out = append(out, window)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Kind == "short" && out[j].Kind == "long" })
	// An API-key credential has no subscription windows to wait for.
	if len(out) == 0 && a.AuthKind() != AuthKindAPIKey {
		for _, spec := range quotaWindowSpecs {
			if spec.provider != provider {
				continue
			}
			long, label := quotaWindowKind(spec, nil)
			window := RoutingWindow{Kind: "short", Label: label, ReservePercent: s.reserve(long)}
			if long {
				window.Kind = "long"
			}
			out = append(out, window)
		}
	}
	return out
}
