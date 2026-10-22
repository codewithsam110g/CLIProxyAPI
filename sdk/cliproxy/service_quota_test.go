package cliproxy

import (
	"context"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func newQuotaPolicyService(t *testing.T, cfg *config.Config) *Service {
	t.Helper()
	cfg.AuthDir = t.TempDir()
	state := normalizedRoutingRuntimeState(cfg)
	manager := coreauth.NewManager(nil, newRoutingSelector(state), nil)
	service := &Service{cfg: cfg, coreManager: manager, appliedRoutingState: &state}
	service.quotaPoller = newQuotaPoller(service)
	manager.SetQuotaPoller(service.quotaPoller)
	t.Cleanup(func() {
		service.quotaPoller.Stop()
		if stoppable, ok := manager.Selector().(coreauth.StoppableSelector); ok {
			stoppable.Stop()
		}
	})
	return service
}

func (s *Service) applyForTest(t *testing.T, cfg *config.Config) {
	t.Helper()
	if !s.applyManagerConfig(context.Background(), configCommit{cfg: cfg, sequence: 1}) {
		t.Fatal("applyManagerConfig failed")
	}
}

func parseQuotaConfig(t *testing.T, raw string) *config.Config {
	t.Helper()
	cfg, err := config.ParseConfigBytes([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestApplyQuotaPolicyDefaultsAndHotReload(t *testing.T) {
	initial := parseQuotaConfig(t, "routing: {strategy: session-balanced}\n")
	service := newQuotaPolicyService(t, initial)
	service.applyQuotaPolicy(initial)
	balanced := service.coreManager.Selector().(*coreauth.SessionBalancedSelector)
	if got := balanced.QuotaReserves(); got != (coreauth.SessionQuotaReserves{Short: 5, Long: 2}) {
		t.Fatalf("default reserves = %+v", got)
	}
	if got := service.quotaPoller.Interval(); got != 5*time.Minute {
		t.Fatalf("default interval = %v", got)
	}

	// Edit through the same path a config reload takes: no new selector, no restart.
	edited := parseQuotaConfig(t, "routing:\n  strategy: session-balanced\n  session-quota:\n    short-window-reserve-percent: 8\n    long-window-reserve-percent: 0\n    poll-interval: 2m\n")
	edited.AuthDir = initial.AuthDir
	service.applyForTest(t, edited)
	if service.coreManager.Selector() != coreauth.Selector(balanced) {
		t.Fatal("changing reserves or the poll interval replaced the selector and dropped its state")
	}
	if got := balanced.QuotaReserves(); got != (coreauth.SessionQuotaReserves{Short: 8, Long: 0}) {
		t.Fatalf("reserves not applied: %+v", got)
	}
	if got := service.quotaPoller.Interval(); got != 2*time.Minute {
		t.Fatalf("interval not applied: %v", got)
	}

	// 0 disables background polling; the reserves keep applying.
	off := parseQuotaConfig(t, "routing:\n  strategy: session-balanced\n  session-quota:\n    poll-interval: 0\n")
	off.AuthDir = initial.AuthDir
	service.applyForTest(t, off)
	if got := service.quotaPoller.Interval(); got != 0 {
		t.Fatalf("polling not disabled: %v", got)
	}
	if got := balanced.QuotaReserves(); got != (coreauth.SessionQuotaReserves{Short: 5, Long: 2}) {
		t.Fatalf("removed settings must return to the defaults: %+v", got)
	}
}

func TestApplyQuotaPolicyPollsOnlyWhileSessionBalancedAndNotInHomeMode(t *testing.T) {
	cfg := parseQuotaConfig(t, "routing: {strategy: session-balanced}\n")
	service := newQuotaPolicyService(t, cfg)
	service.applyQuotaPolicy(cfg)
	if service.quotaPoller.Interval() == 0 {
		t.Fatal("setup: polling should be on")
	}

	other := parseQuotaConfig(t, "routing: {strategy: fill-first}\n")
	service.applyForTest(t, other)
	if got := service.quotaPoller.Interval(); got != 0 {
		t.Fatalf("polling continues under fill-first: %v", got)
	}

	// Switching back installs a fresh selector, which must receive the configured reserves.
	back := parseQuotaConfig(t, "routing:\n  strategy: session-balanced\n  session-quota:\n    short-window-reserve-percent: 9\n")
	back.AuthDir = other.AuthDir
	service.applyForTest(t, back)
	balanced, ok := service.coreManager.Selector().(*coreauth.SessionBalancedSelector)
	if !ok {
		t.Fatalf("selector = %T", service.coreManager.Selector())
	}
	if got := balanced.QuotaReserves(); got.Short != 9 || got.Long != 2 {
		t.Fatalf("new selector missed the configured reserves: %+v", got)
	}
	if service.quotaPoller.Interval() != 5*time.Minute {
		t.Fatalf("polling not resumed: %v", service.quotaPoller.Interval())
	}

	home := parseQuotaConfig(t, "routing: {strategy: session-balanced}\n")
	home.AuthDir = other.AuthDir
	home.Home.Enabled = true
	service.applyQuotaPolicy(home)
	if got := service.quotaPoller.Interval(); got != 0 {
		t.Fatalf("polling in Home mode: %v", got)
	}
}

func TestBuilderWiresQuotaPoller(t *testing.T) {
	cfg := parseQuotaConfig(t, "routing: {strategy: session-balanced}\n")
	cfg.AuthDir = t.TempDir()
	service, err := NewBuilder().WithConfig(cfg).WithConfigPath(t.TempDir() + "/config.yaml").Build()
	if err != nil {
		t.Fatal(err)
	}
	defer service.quotaPoller.Stop()
	if service.quotaPoller == nil || service.coreManager.QuotaPoller() != service.quotaPoller {
		t.Fatal("poller not registered with the manager")
	}
	if got := service.quotaPoller.Interval(); got != 5*time.Minute {
		t.Fatalf("builder did not apply the default interval: %v", got)
	}
	if balanced, ok := service.coreManager.Selector().(*coreauth.SessionBalancedSelector); ok {
		defer balanced.Stop()
	}
}
