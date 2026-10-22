package config

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// Defaults and bounds for routing.session-quota.
const (
	// DefaultSessionQuotaShortReservePercent stops an account whose short quota
	// window (Claude 5-hour, Codex primary) has this much or less remaining.
	DefaultSessionQuotaShortReservePercent = 5.0
	// DefaultSessionQuotaLongReservePercent is the same threshold for the long
	// window (Claude 7-day, Codex secondary).
	DefaultSessionQuotaLongReservePercent = 2.0
	// MaxSessionQuotaReservePercent bounds both reserves; above it an account
	// would be stopped while most of its window is still unused.
	MaxSessionQuotaReservePercent = 50.0
	// DefaultSessionQuotaPollInterval is how often provider usage is polled.
	DefaultSessionQuotaPollInterval = 5 * time.Minute
	// MinSessionQuotaPollInterval is the shortest accepted non-zero interval.
	MinSessionQuotaPollInterval = time.Minute
)

// SessionQuotaConfig tunes how the session-balanced strategy reacts to provider
// quota windows. Reserves are percentages of the window that must remain: an
// account at or below its reserve is stopped for new and existing conversations.
//
// The reserve fields are pointers because 0 is meaningful ("stop only when the
// window is fully used"); nil selects the default. An empty PollInterval selects
// the default, and "0" disables background polling (the on-demand refresh
// endpoint keeps working).
type SessionQuotaConfig struct {
	// ShortWindowReservePercent applies to the Claude 5-hour and Codex primary windows.
	ShortWindowReservePercent *float64 `yaml:"short-window-reserve-percent,omitempty" json:"short-window-reserve-percent,omitempty"`
	// LongWindowReservePercent applies to the Claude 7-day and Codex secondary windows.
	LongWindowReservePercent *float64 `yaml:"long-window-reserve-percent,omitempty" json:"long-window-reserve-percent,omitempty"`
	// PollInterval is a duration string such as "5m". "0" disables background polling.
	PollInterval string `yaml:"poll-interval,omitempty" json:"poll-interval,omitempty"`
}

// Validate rejects out-of-range values, like the other structured routing and
// credential settings, so a bad write fails visibly instead of being silently
// replaced by a different effective value.
func (c SessionQuotaConfig) Validate() error {
	for _, field := range []struct {
		name  string
		value *float64
	}{
		{"short-window-reserve-percent", c.ShortWindowReservePercent},
		{"long-window-reserve-percent", c.LongWindowReservePercent},
	} {
		if field.value == nil {
			continue
		}
		if v := *field.value; math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > MaxSessionQuotaReservePercent {
			return fmt.Errorf("routing.session-quota.%s must be between 0 and %g", field.name, MaxSessionQuotaReservePercent)
		}
	}
	if raw := strings.TrimSpace(c.PollInterval); raw != "" {
		interval, err := time.ParseDuration(raw)
		if err != nil {
			return fmt.Errorf("routing.session-quota.poll-interval %q is not a duration such as \"5m\" (use \"0\" to disable)", raw)
		}
		if interval < 0 || (interval > 0 && interval < MinSessionQuotaPollInterval) {
			return fmt.Errorf("routing.session-quota.poll-interval must be 0 (disabled) or at least %s", MinSessionQuotaPollInterval)
		}
	}
	return nil
}

// ShortReservePercent returns the effective short-window reserve. Validate
// rejects bad input at load; the clamp only protects programmatic configs.
func (c SessionQuotaConfig) ShortReservePercent() float64 {
	return effectiveReserve(c.ShortWindowReservePercent, DefaultSessionQuotaShortReservePercent)
}

// LongReservePercent returns the effective long-window reserve.
func (c SessionQuotaConfig) LongReservePercent() float64 {
	return effectiveReserve(c.LongWindowReservePercent, DefaultSessionQuotaLongReservePercent)
}

// EffectivePollInterval returns the polling cadence, or 0 when polling is disabled.
func (c SessionQuotaConfig) EffectivePollInterval() time.Duration {
	raw := strings.TrimSpace(c.PollInterval)
	if raw == "" {
		return DefaultSessionQuotaPollInterval
	}
	interval, err := time.ParseDuration(raw)
	if err != nil || interval < 0 {
		return DefaultSessionQuotaPollInterval
	}
	if interval > 0 && interval < MinSessionQuotaPollInterval {
		return MinSessionQuotaPollInterval
	}
	return interval
}

func effectiveReserve(value *float64, fallback float64) float64 {
	if value == nil || math.IsNaN(*value) || math.IsInf(*value, 0) {
		return fallback
	}
	return math.Min(math.Max(*value, 0), MaxSessionQuotaReservePercent)
}
