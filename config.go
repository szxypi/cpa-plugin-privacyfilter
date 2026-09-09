package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/scan"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const privacyFilterProvider = "privacyfilter"
const pluginName = "privacyfilter"

const (
	defaultMaxBodyBytes = int64(4 << 20) // 4 MiB
	defaultCacheEntries = 4096
	defaultCacheBytes   = int64(64 << 20) // 64 MiB of redacted output
	defaultMaxWorkers   = 4
)

type privacyFilterConfig struct {
	GitleaksTOML string   `yaml:"gitleaks_toml"`
	SkipModels   []string `yaml:"skip_models"`
	SkipFormats  []string `yaml:"skip_formats"`
	// DisableRules drops gitleaks rules by id. "generic-api-key" is both the
	// most expensive rule in the set and its biggest source of false
	// positives; dropping it roughly halves scan time.
	DisableRules []string `yaml:"disable_rules"`
	// MaxBodyBytes skips bodies larger than this. 0 means no limit.
	MaxBodyBytes *int64 `yaml:"max_body_bytes"`
	// ScanToolInput includes tool-call arguments and tool results.
	ScanToolInput *bool `yaml:"scan_tool_input"`
	// CacheEntries bounds the content cache. 0 disables it.
	CacheEntries *int   `yaml:"cache_entries"`
	CacheBytes   *int64 `yaml:"cache_bytes"`
	// Workers bounds the goroutines used to scan one request's fields.
	Workers *int `yaml:"workers"`
	// LogStats emits a debug line for clean requests too.
	LogStats bool `yaml:"log_stats"`
}

func defaultConfig() privacyFilterConfig {
	return privacyFilterConfig{}
}

func parseConfig(raw []byte) (privacyFilterConfig, error) {
	cfg := defaultConfig()
	if len(strings.TrimSpace(string(raw))) > 0 {
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			return cfg, fmt.Errorf("invalid privacyfilter config: %w", err)
		}
	}
	return cfg, nil
}

func (cfg *privacyFilterConfig) maxBodyBytes() int64 {
	if cfg.MaxBodyBytes == nil {
		return defaultMaxBodyBytes
	}
	if *cfg.MaxBodyBytes < 0 {
		return 0
	}
	return *cfg.MaxBodyBytes
}

func (cfg *privacyFilterConfig) scanToolInput() bool {
	if cfg.ScanToolInput == nil {
		return true
	}
	return *cfg.ScanToolInput
}

func (cfg *privacyFilterConfig) cacheEntries() int {
	if cfg.CacheEntries == nil {
		return defaultCacheEntries
	}
	if *cfg.CacheEntries < 0 {
		return 0
	}
	return *cfg.CacheEntries
}

func (cfg *privacyFilterConfig) cacheBytes() int64 {
	if cfg.CacheBytes == nil || *cfg.CacheBytes <= 0 {
		return defaultCacheBytes
	}
	return *cfg.CacheBytes
}

func (cfg *privacyFilterConfig) workers() int {
	limit := runtime.NumCPU()
	want := defaultMaxWorkers
	if cfg.Workers != nil {
		want = *cfg.Workers
	}
	if want <= 0 {
		return 1
	}
	if want > limit {
		return limit
	}
	return want
}

// resolveGitleaksPath resolves the configured gitleaks rule file. The return is
// split into a path (may be empty) and an embedded flag: when the path is empty
// and embedded is true, the caller should load the rules baked into the binary.
func (cfg *privacyFilterConfig) resolveGitleaksPath(pluginDir string) (path string, embedded bool) {
	if cfg.GitleaksTOML == "" {
		builtin := filepath.Join(pluginDir, "rules", "gitleaks.toml")
		if _, err := os.Stat(builtin); err == nil {
			return builtin, false
		}
		// No sidecar file: fall back to the rules compiled into the binary.
		return "", true
	}
	if filepath.IsAbs(cfg.GitleaksTOML) {
		return cfg.GitleaksTOML, false
	}
	return filepath.Join(pluginDir, cfg.GitleaksTOML), false
}

func (cfg *privacyFilterConfig) shouldSkip(model, requestedModel, format string) bool {
	for _, m := range cfg.SkipModels {
		trimmed := strings.TrimSpace(m)
		if strings.EqualFold(trimmed, model) || strings.EqualFold(trimmed, requestedModel) {
			return true
		}
	}
	for _, f := range cfg.SkipFormats {
		if strings.EqualFold(strings.TrimSpace(f), format) {
			return true
		}
	}
	return false
}

// newScanner compiles the rule set once, at configuration load time. The
// returned scanner is immutable and safe to share across requests.
func newScanner(pluginDir string, cfg privacyFilterConfig) (*scan.Scanner, error) {
	document := embeddedGitleaks
	source := "embedded"
	if tomlPath, embedded := cfg.resolveGitleaksPath(pluginDir); !embedded {
		raw, err := os.ReadFile(tomlPath)
		if err != nil {
			return nil, fmt.Errorf("read gitleaks rules %s: %w", tomlPath, err)
		}
		document = raw
		source = tomlPath
	}
	rules, skipped, err := scan.LoadRules(document, cfg.DisableRules)
	if err != nil {
		return nil, fmt.Errorf("failed to create privacy filter: %w", err)
	}
	scanner := scan.New(rules, skipped)
	loaded, skippedCount := scanner.Stats()
	log.Infof("privacy filter loaded: %d rules, %d skipped (source=%s, disabled=%v)",
		loaded, skippedCount, source, cfg.DisableRules)
	return scanner, nil
}
