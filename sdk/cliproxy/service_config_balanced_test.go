package cliproxy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestSessionBalancedDeploymentConfig(t *testing.T) {
	for _, name := range []string{"docker", "native"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", "deploy", "tailnet", "config."+name+".example.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err = os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			state := normalizedRoutingRuntimeState(cfg)
			if state.strategy != "session-balanced" || state.sessionAffinityTTL != 24*time.Hour || state.sessionStatePath != filepath.Join(cfg.AuthDir, ".session-affinity.state") {
				t.Fatalf("wrong routing config: %+v", state)
			}
			if cfg.Port != 8317 || cfg.AuthDir == "" || len(cfg.APIKeys) != 1 || !cfg.RemoteManagement.DisableAutoUpdatePanel {
				t.Fatal("deployment config lost persistent/auth/panel settings")
			}
			if name == "native" && (cfg.Host != "127.0.0.1" || cfg.RemoteManagement.AllowRemote) {
				t.Fatal("native gateway must be loopback-only")
			}
			if name == "docker" && (cfg.Host != "0.0.0.0" || !cfg.RemoteManagement.AllowRemote) {
				t.Fatal("container listener must accept bridge traffic")
			}
		})
	}
}

func TestSessionBalancedRoutingConstruction(t *testing.T) {
	cfg := &config.Config{}
	cfg.Routing.Strategy = "session-balanced"
	cfg.AuthDir = t.TempDir()
	selector := newRoutingSelector(normalizedRoutingRuntimeState(cfg))
	balanced, ok := selector.(*coreauth.SessionBalancedSelector)
	if !ok {
		t.Fatalf("unexpected selector %T", selector)
	}
	balanced.Stop()
}
