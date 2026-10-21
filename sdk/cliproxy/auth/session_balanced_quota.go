package auth

import (
	"errors"
	"math"
	"strconv"
	"strings"
	"time"
)

const sessionQuotaReservePercent = 1.0

// Quota stops outlive the short scoring snapshot. A missing observation cannot
// make a stopped account usable again; its window must reset or report recovery.
type sessionQuotaStop struct {
	RemainingPercent float64   `json:"remaining_percent"`
	ObservedAt       time.Time `json:"observed_at"`
	ResetAt          time.Time `json:"reset_at,omitempty"`
	Reason           string    `json:"reason"`
}

func validSessionQuotaStop(name string, stop sessionQuotaStop) bool {
	switch name {
	case "confirmed", "anthropic-ratelimit-unified-5h-utilization", "anthropic-ratelimit-unified-7d-utilization", "x-codex-primary-used-percent", "x-codex-secondary-used-percent":
	default:
		return false
	}
	return !stop.ObservedAt.IsZero() && stop.Reason != "" && stop.RemainingPercent >= 0 && stop.RemainingPercent <= sessionQuotaReservePercent
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

func quotaWindowObservations(a *Auth) map[string]sessionQuotaStop {
	windows := make(map[string]sessionQuotaStop)
	if a == nil {
		return windows
	}
	signals := make(map[string]string, len(a.Quota.Signals))
	for k, v := range a.Quota.Signals {
		signals[strings.ToLower(k)] = v
	}
	for _, spec := range []struct {
		key, reset string
		fraction   bool
	}{
		{"anthropic-ratelimit-unified-5h-utilization", "anthropic-ratelimit-unified-5h-reset", true},
		{"anthropic-ratelimit-unified-7d-utilization", "anthropic-ratelimit-unified-7d-reset", true},
		{"x-codex-primary-used-percent", "x-codex-primary-reset-at", false},
		{"x-codex-secondary-used-percent", "x-codex-secondary-reset-at", false},
	} {
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
		windows[spec.key] = sessionQuotaStop{RemainingPercent: math.Max(0, 100-used), ObservedAt: a.Quota.ObservedAt, ResetAt: reset, Reason: "quota reserve reached (1% remaining or less)"}
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

// Caller holds s.mu. Manager snapshots include excluded accounts, so every
// conversation can recognize a confirmed account-wide quota failure.
func (s *SessionBalancedSelector) refreshQuotaStops(candidates []*Auth, now time.Time) bool {
	if s.state.QuotaStops == nil {
		s.state.QuotaStops = make(map[string]map[string]sessionQuotaStop)
	}
	changed := false
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
			if observation.RemainingPercent <= sessionQuotaReservePercent {
				allHealthy = false
				if !observation.ResetAt.IsZero() && !now.Before(observation.ResetAt) {
					continue
				}
				if !exists || observation.ObservedAt.After(old.ObservedAt) {
					windows[name] = observation
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
		}
	}
	return changed
}

func (s *SessionBalancedSelector) quotaStopReason(id string) string {
	windows := s.state.QuotaStops[id]
	if stop, ok := windows["confirmed"]; ok {
		return stop.Reason
	}
	if len(windows) > 0 {
		return "quota reserve reached (1% remaining or less)"
	}
	return ""
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
			if window.RemainingPercent <= sessionQuotaReservePercent && window.ResetAt.After(s.now()) && window.ResetAt.After(reset) {
				reset = window.ResetAt
			}
		}
	}
	if old := s.state.QuotaStops[r.AuthID]["confirmed"]; old.ResetAt.After(s.now()) && old.ResetAt.After(reset) {
		reset = old.ResetAt
	}
	s.state.QuotaStops[r.AuthID]["confirmed"] = sessionQuotaStop{ObservedAt: s.now(), ResetAt: reset, Reason: "confirmed quota exhaustion"}
}
