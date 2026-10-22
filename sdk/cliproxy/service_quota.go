package cliproxy

import (
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

// newQuotaPoller builds the poller with the Claude and Codex usage probes.
func newQuotaPoller(s *Service) *coreauth.QuotaPoller {
	probes := helps.UsageProbes{Config: s.currentConfig}
	return coreauth.NewQuotaPoller(s.coreManager, map[string]coreauth.QuotaProbe{
		"claude": probes.Claude,
		"codex":  probes.Codex,
	})
}

// applyQuotaPolicy applies routing.session-quota. Reserves go to the active
// session-balanced selector. Background polling runs only while that strategy is
// selected, since nothing else reads the observation for routing, and never in
// Home mode, where this process does not own the credentials. The on-demand
// refresh endpoint works whenever the poller exists.
//
// The caller serializes it with selector replacement (configRuntimeMu).
func (s *Service) applyQuotaPolicy(cfg *config.Config) {
	if s == nil || s.coreManager == nil || cfg == nil {
		return
	}
	quota := cfg.Routing.SessionQuota
	reserves := coreauth.SessionQuotaReserves{Short: quota.ShortReservePercent(), Long: quota.LongReservePercent()}
	balanced, _ := s.coreManager.Selector().(*coreauth.SessionBalancedSelector)
	reservesChanged := false
	if balanced != nil {
		reservesChanged = balanced.QuotaReserves() != reserves
		balanced.SetQuotaReserves(reserves)
	}
	if s.quotaPoller == nil {
		return
	}
	interval := quota.EffectivePollInterval()
	if balanced == nil || cfg.Home.Enabled {
		interval = 0
	}
	s.quotaPoller.Configure(interval)
	// A lowered reserve only releases a stop once a fresh observation confirms
	// the window is above it, so fetch one now instead of waiting for the next tick.
	if reservesChanged && interval > 0 {
		s.quotaPoller.PollAllAsync()
	}
}
