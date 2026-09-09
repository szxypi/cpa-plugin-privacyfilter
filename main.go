package main

import (
	"github.com/rheodev/cpa-plugin-privacyfilter/internal/scan"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

var pluginVersion = "0.3.0"

func buildPlugin(configYAML []byte, pluginDir string) (pluginapi.Plugin, error) {
	cfg, errParse := parseConfig(configYAML)
	if errParse != nil {
		return pluginapi.Plugin{}, errParse
	}
	if pluginDir == "" {
		pluginDir = inferPluginDir()
	}

	scanner, errScanner := newScanner(pluginDir, cfg)
	if errScanner != nil {
		return pluginapi.Plugin{}, errScanner
	}

	p := &privacyFilterPlugin{
		cfg:       cfg,
		pluginDir: pluginDir,
		scanner:   scanner,
		cache:     scan.NewCache(cfg.cacheEntries(), cfg.cacheBytes()),
	}

	return pluginapi.Plugin{
		Metadata: pluginapi.Metadata{
			Name:             pluginName,
			Version:          pluginVersion,
			Author:           "rheodev",
			GitHubRepository: "https://github.com/rheodev/cpa-plugin-privacyfilter",
			ConfigFields: []pluginapi.ConfigField{
				{
					Name:        "gitleaks_toml",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "Path to gitleaks.toml rules file. Empty uses built-in rules.",
				},
				{
					Name:        "skip_models",
					Type:        pluginapi.ConfigFieldTypeArray,
					Description: "Model names to skip redaction for.",
				},
				{
					Name:        "skip_formats",
					Type:        pluginapi.ConfigFieldTypeArray,
					Description: "Source format names to skip redaction for.",
				},
				{
					Name:        "disable_rules",
					Type:        pluginapi.ConfigFieldTypeArray,
					Description: "Gitleaks rule ids to drop. Dropping generic-api-key roughly halves scan time.",
				},
				{
					Name:        "max_body_bytes",
					Type:        pluginapi.ConfigFieldTypeInteger,
					Description: "Skip request bodies larger than this many bytes. Default 4194304, negative means no limit.",
				},
				{
					Name:        "scan_tool_input",
					Type:        pluginapi.ConfigFieldTypeBoolean,
					Description: "Scan tool-call arguments and tool results as well as message text. Default true.",
				},
				{
					Name:        "cache_entries",
					Type:        pluginapi.ConfigFieldTypeInteger,
					Description: "Number of scanned texts remembered between requests. Default 4096, 0 disables the cache.",
				},
				{
					Name:        "cache_bytes",
					Type:        pluginapi.ConfigFieldTypeInteger,
					Description: "Byte budget for cached redacted text. Default 67108864.",
				},
				{
					Name:        "workers",
					Type:        pluginapi.ConfigFieldTypeInteger,
					Description: "Goroutines used to scan one request's fields, capped at NumCPU. Default 4.",
				},
				{
					Name:        "log_stats",
					Type:        pluginapi.ConfigFieldTypeBoolean,
					Description: "Log a debug line for clean requests too. Redactions are always logged.",
				},
			},
		},
		Capabilities: pluginapi.Capabilities{
			RequestInterceptor: p,
		},
	}, nil
}
