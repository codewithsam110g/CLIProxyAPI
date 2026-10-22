package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSessionQuotaDefaultsWhenOmitted(t *testing.T) {
	for _, raw := range []string{"port: 8317\n", "routing: {strategy: session-balanced}\n", "routing: {strategy: session-balanced, session-quota: {}}\n"} {
		cfg, err := ParseConfigBytes([]byte(raw))
		if err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
		q := cfg.Routing.SessionQuota
		if q.ShortReservePercent() != 5 || q.LongReservePercent() != 2 || q.EffectivePollInterval() != 5*time.Minute {
			t.Fatalf("%q: defaults = %v/%v/%v", raw, q.ShortReservePercent(), q.LongReservePercent(), q.EffectivePollInterval())
		}
	}
}

func TestSessionQuotaParsesExplicitValuesIncludingZero(t *testing.T) {
	cfg, err := ParseConfigBytes([]byte("routing:\n  session-quota:\n    short-window-reserve-percent: 0\n    long-window-reserve-percent: 7.5\n    poll-interval: \"0\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	q := cfg.Routing.SessionQuota
	if q.ShortWindowReservePercent == nil || q.ShortReservePercent() != 0 {
		t.Fatalf("explicit zero reserve lost: %+v", q)
	}
	if q.LongReservePercent() != 7.5 {
		t.Fatalf("long reserve = %v", q.LongReservePercent())
	}
	if q.EffectivePollInterval() != 0 {
		t.Fatalf("poll interval 0 must disable polling, got %v", q.EffectivePollInterval())
	}
	// An unquoted YAML 0 decodes into the string field as well.
	cfg, err = ParseConfigBytes([]byte("routing: {session-quota: {poll-interval: 0}}\n"))
	if err != nil || cfg.Routing.SessionQuota.EffectivePollInterval() != 0 {
		t.Fatalf("unquoted zero interval: %v %+v", err, cfg)
	}
	cfg, err = ParseConfigBytes([]byte("routing: {session-quota: {poll-interval: 90s}}\n"))
	if err != nil || cfg.Routing.SessionQuota.EffectivePollInterval() != 90*time.Second {
		t.Fatalf("90s interval: %v", err)
	}
}

func TestSessionQuotaRejectsInvalidValues(t *testing.T) {
	for _, tc := range []struct{ name, yaml, want string }{
		{"short negative", "short-window-reserve-percent: -1", "short-window-reserve-percent"},
		{"short above max", "short-window-reserve-percent: 50.5", "short-window-reserve-percent"},
		{"long above max", "long-window-reserve-percent: 75", "long-window-reserve-percent"},
		{"nan", "long-window-reserve-percent: .nan", "long-window-reserve-percent"},
		{"interval garbage", "poll-interval: soon", "poll-interval"},
		{"interval bare number", "poll-interval: 300", "poll-interval"},
		{"interval below minimum", "poll-interval: 30s", "at least 1m0s"},
		{"interval negative", "poll-interval: -5m", "poll-interval"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseConfigBytes([]byte("routing:\n  session-quota:\n    " + tc.yaml + "\n"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
			path := writeUploadTestConfig(t, "routing:\n  session-quota:\n    "+tc.yaml+"\n")
			if _, err = LoadConfig(path); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadConfig: want error containing %q, got %v", tc.want, err)
			}
		})
	}
	for _, ok := range []string{"short-window-reserve-percent: 0", "short-window-reserve-percent: 50", "poll-interval: 1m", "poll-interval: 0s", "poll-interval: 24h"} {
		if _, err := ParseConfigBytes([]byte("routing:\n  session-quota:\n    " + ok + "\n")); err != nil {
			t.Fatalf("%s rejected: %v", ok, err)
		}
	}
}

func TestSessionQuotaAccessorsClampProgrammaticValues(t *testing.T) {
	over, under := 99.0, -3.0
	q := SessionQuotaConfig{ShortWindowReservePercent: &over, LongWindowReservePercent: &under, PollInterval: "10s"}
	if q.ShortReservePercent() != 50 || q.LongReservePercent() != 0 || q.EffectivePollInterval() != time.Minute {
		t.Fatalf("clamps: %v %v %v", q.ShortReservePercent(), q.LongReservePercent(), q.EffectivePollInterval())
	}
	if got := (SessionQuotaConfig{PollInterval: "garbage"}).EffectivePollInterval(); got != 5*time.Minute {
		t.Fatalf("unparsable interval = %v", got)
	}
}

func TestSessionQuotaSaveRoundTripPreservesExplicitZeroAndComments(t *testing.T) {
	path := writeUploadTestConfig(t, "# keep this comment\nport: 8317\nrouting:\n  strategy: session-balanced\n")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	zero, long := 0.0, 3.0
	cfg.Routing.SessionQuota = SessionQuotaConfig{ShortWindowReservePercent: &zero, LongWindowReservePercent: &long, PollInterval: "0"}
	if err = SaveConfigPreserveComments(path, cfg); err != nil {
		t.Fatal(err)
	}
	saved := readUploadTestConfig(t, path)
	for _, want := range []string{"# keep this comment", "session-quota:", "short-window-reserve-percent: 0", "long-window-reserve-percent: 3", "poll-interval: \"0\""} {
		if !strings.Contains(saved, want) {
			t.Fatalf("saved config missing %q:\n%s", want, saved)
		}
	}
	reloaded, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	q := reloaded.Routing.SessionQuota
	if q.ShortWindowReservePercent == nil || *q.ShortWindowReservePercent != 0 || q.LongReservePercent() != 3 || q.EffectivePollInterval() != 0 {
		t.Fatalf("round trip changed values: %+v", q)
	}
}

func TestSessionQuotaSaveRoundTripWithoutRoutingSection(t *testing.T) {
	// routing and session-quota are both new keys here; the explicit zero must
	// survive the new-key pruning of zero values.
	path := writeUploadTestConfig(t, "port: 8317\n")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	zero := 0.0
	cfg.Routing.SessionQuota.LongWindowReservePercent = &zero
	if err = SaveConfigPreserveComments(path, cfg); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.Routing.SessionQuota.LongWindowReservePercent; got == nil || *got != 0 {
		t.Fatalf("explicit zero reserve pruned:\n%s", readUploadTestConfig(t, path))
	}
	if got := reloaded.Routing.SessionQuota.ShortReservePercent(); got != 5 {
		t.Fatalf("unset short reserve = %v", got)
	}
}

func TestSessionQuotaDefaultsDoNotPolluteSavedConfig(t *testing.T) {
	path := writeUploadTestConfig(t, "port: 8317\n")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = SaveConfigPreserveComments(path, cfg); err != nil {
		t.Fatal(err)
	}
	if saved := readUploadTestConfig(t, path); strings.Contains(saved, "session-quota") {
		t.Fatalf("unset quota settings were written:\n%s", saved)
	}
}

func TestSessionQuotaV8LayoutAndCloneRoundTrip(t *testing.T) {
	raw := "config-version: 8\nrouting:\n  strategy: session-balanced\n  session-quota:\n    short-window-reserve-percent: 4\n    poll-interval: 2m\n"
	if err := ValidateV8Config([]byte(raw)); err != nil {
		t.Fatalf("v8 validation rejected the new keys: %v", err)
	}
	cfg, err := ParseConfigBytes([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	clone := cfg.CloneForRuntime()
	if got := clone.Routing.SessionQuota; got.ShortReservePercent() != 4 || got.EffectivePollInterval() != 2*time.Minute || got.ShortWindowReservePercent == cfg.Routing.SessionQuota.ShortWindowReservePercent {
		t.Fatalf("clone must copy the pointer-backed reserve: %+v", got)
	}
	data, _, err := NormalizeConfigLayout([]byte(raw), true)
	if err != nil || !strings.Contains(string(data), "short-window-reserve-percent: 4") {
		t.Fatalf("v8 normalization dropped the keys: %v\n%s", err, data)
	}
	if err = ValidateV8Config([]byte("routing:\n  session-quota:\n    unknown-key: 1\nconfig-version: 8\n")); err == nil {
		t.Fatal("unknown session-quota key accepted by strict v8 validation")
	}
}

func TestSessionQuotaExampleConfigDocumentsTheDefaults(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateV8Config(data); err != nil {
		t.Fatalf("example config fails strict v8 validation: %v", err)
	}
	cfg, err := ParseConfigBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	q := cfg.Routing.SessionQuota
	if q.ShortWindowReservePercent == nil || *q.ShortWindowReservePercent != DefaultSessionQuotaShortReservePercent ||
		q.LongWindowReservePercent == nil || *q.LongWindowReservePercent != DefaultSessionQuotaLongReservePercent ||
		q.EffectivePollInterval() != DefaultSessionQuotaPollInterval {
		t.Fatalf("example values drifted from the code defaults: %+v", q)
	}
}
