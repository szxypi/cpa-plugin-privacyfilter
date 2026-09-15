package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

var pluginVersion = "0.4.0"

// assemblePlugin builds a plugin instance around a vault chosen by vaultFor.
func assemblePlugin(cfg privacyFilterConfig, pluginDir string, states *stateRegistry, vaultFor func(*placeholderFormat) *vault) (*privacyFilterPlugin, error) {
	format, errFormat := newPlaceholderFormat(cfg.PlaceholderStyle, cfg.PlaceholderPrefix)
	if errFormat != nil {
		return nil, errFormat
	}
	skipTypes, errSkip := cfg.skipTypes()
	if errSkip != nil {
		return nil, errSkip
	}
	scanner, errScanner := newScanner(pluginDir, cfg)
	if errScanner != nil {
		return nil, errScanner
	}
	p := &privacyFilterPlugin{
		cfg:       cfg,
		pluginDir: pluginDir,
		format:    format,
		analyzer:  &analyzer{scanner: scanner, format: format, skipTypes: skipTypes},
		cache:     newAnalysisCache(cfg.cacheEntries(), cfg.cacheBytes()),
		vault:     vaultFor(format),
		states:    states,
	}
	if cfg.notice() {
		p.notice = noticeText(format)
	}
	return p, nil
}

// shared survives plugin.reconfigure: in-flight requests keep their states,
// and the vault keeps its values as long as placeholders render the same way.
var shared = struct {
	sync.Mutex
	states   *stateRegistry
	vault    *vault
	vaultKey string
}{states: newStateRegistry()}

func buildPlugin(configYAML []byte, pluginDir string) (pluginapi.Plugin, error) {
	cfg, errParse := parseConfig(configYAML)
	if errParse != nil {
		return pluginapi.Plugin{}, errParse
	}
	if pluginDir == "" {
		pluginDir = inferPluginDir()
	}
	dataDir := cfg.dataDir()
	if !filepath.IsAbs(dataDir) {
		if wd, err := os.Getwd(); err == nil {
			dataDir = filepath.Join(wd, dataDir)
		}
	}
	p, errAssemble := assemblePlugin(cfg, pluginDir, shared.states, func(format *placeholderFormat) *vault {
		shared.Lock()
		defer shared.Unlock()
		vaultKey := fmt.Sprintf("%s|%s|%s|%d|%d", format.style, format.prefix, dataDir, cfg.vaultMaxEntries(), cfg.literalMinBytes())
		if shared.vault == nil || shared.vaultKey != vaultKey {
			key, errKey := loadOrCreateKey(dataDir)
			if errKey != nil {
				log.Warnf("privacyfilter: cannot use placeholder key in %s (%v); placeholders will change after a restart", dataDir, errKey)
				key = ephemeralKey()
			}
			shared.vault = newVault(format, key, cfg.vaultMaxEntries(), cfg.literalMinBytes())
			shared.vaultKey = vaultKey
		}
		return shared.vault
	})
	if errAssemble != nil {
		return pluginapi.Plugin{}, errAssemble
	}
	log.Infof("privacy filter mode: placeholder style=%s restore=%v notice=%v data_dir=%s",
		p.format.style, cfg.restoreResponses(), cfg.notice(), dataDir)

	return pluginapi.Plugin{
		Metadata: pluginapi.Metadata{
			Name:             pluginName,
			Version:          pluginVersion,
			Author:           "rheodev, szxypi",
			GitHubRepository: "https://github.com/szxypi/cpa-plugin-privacyfilter",
			ConfigFields: []pluginapi.ConfigField{
				{
					Name:        "placeholder_style",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "占位符样式：short（默认，形如 pf-key-3a7f9c21d0b4，模型复制更准）或 uuid。",
				},
				{
					Name:        "placeholder_prefix",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "short 样式的前缀，1-16 位小写字母或数字，默认 pf。修改会让所有占位符变化（一次性缓存未命中）。",
				},
				{
					Name:        "restore_responses",
					Type:        pluginapi.ConfigFieldTypeBoolean,
					Description: "响应（含流式与工具调用参数）里把占位符还原成真实值，默认 true；关闭即变成单向脱敏。",
				},
				{
					Name:        "notice",
					Type:        pluginapi.ConfigFieldTypeBoolean,
					Description: "请求含占位符时在系统提示词末尾追加一段英文说明，让模型原样使用占位符，默认 true。",
				},
				{
					Name:        "skip_types",
					Type:        pluginapi.ConfigFieldTypeArray,
					Description: "不替换的类型：key、email、phone、idcard、ip、card。",
				},
				{
					Name:        "data_dir",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "存放占位符 HMAC 密钥的目录（只存密钥，不存敏感值），相对路径基于 CPA 工作目录，默认 privacyfilter。",
				},
				{
					Name:        "vault_max_entries",
					Type:        pluginapi.ConfigFieldTypeInteger,
					Description: "内存映射表最多保留的敏感值条数，超出按最久未见淘汰，默认 100000。",
				},
				{
					Name:        "literal_min_bytes",
					Type:        pluginapi.ConfigFieldTypeInteger,
					Description: "已识别过的敏感值再次出现时（即使检测器没认出）也替换的最小长度，默认 6，最小 4。",
				},
				{
					Name:        "gitleaks_toml",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "gitleaks.toml 规则文件路径，留空使用内置规则。",
				},
				{
					Name:        "skip_models",
					Type:        pluginapi.ConfigFieldTypeArray,
					Description: "不处理的模型名。",
				},
				{
					Name:        "skip_formats",
					Type:        pluginapi.ConfigFieldTypeArray,
					Description: "不处理的客户端协议格式（claude、openai、openai-response、gemini）。",
				},
				{
					Name:        "disable_rules",
					Type:        pluginapi.ConfigFieldTypeArray,
					Description: "停用的 gitleaks 规则 id；停用 generic-api-key 约省一半扫描时间。",
				},
				{
					Name:        "max_body_bytes",
					Type:        pluginapi.ConfigFieldTypeInteger,
					Description: "超过该字节数的请求体不处理，默认 4194304，负数表示不限。",
				},
				{
					Name:        "scan_tool_input",
					Type:        pluginapi.ConfigFieldTypeBoolean,
					Description: "同时处理工具调用参数与工具结果，默认 true。",
				},
				{
					Name:        "cache_entries",
					Type:        pluginapi.ConfigFieldTypeInteger,
					Description: "按内容哈希缓存的文本检测结果条数，默认 4096，0 关闭缓存。",
				},
				{
					Name:        "cache_bytes",
					Type:        pluginapi.ConfigFieldTypeInteger,
					Description: "检测结果缓存的字节预算，默认 67108864。",
				},
				{
					Name:        "workers",
					Type:        pluginapi.ConfigFieldTypeInteger,
					Description: "单个请求并行扫描字段的协程数，上限为 CPU 数，默认 4。",
				},
				{
					Name:        "log_stats",
					Type:        pluginapi.ConfigFieldTypeBoolean,
					Description: "无敏感值的请求也打 debug 统计日志；有替换时总会打 info 日志（不含敏感值）。",
				},
			},
		},
		Capabilities: pluginapi.Capabilities{
			RequestInterceptor:     p,
			ResponseInterceptor:    p,
			StreamChunkInterceptor: p,
			RequestLifecyclePlugin: p,
		},
	}, nil
}
