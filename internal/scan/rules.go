package scan

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

// Rule is one compiled gitleaks-style detection rule.
type Rule struct {
	ID          string
	Re          *regexp.Regexp
	Keywords    []string // lower-cased; empty means the rule always runs
	Entropy     float64
	SecretGroup int
}

// tomlConfig is the subset of gitleaks.toml this scanner understands. Unknown
// fields (allowlists, descriptions, ...) are ignored.
type tomlConfig struct {
	Rules []struct {
		ID          string   `toml:"id"`
		Regex       string   `toml:"regex"`
		Keywords    []string `toml:"keywords"`
		Entropy     float64  `toml:"entropy"`
		SecretGroup int      `toml:"secretGroup"`
	} `toml:"rules"`
}

// builtinRules mirror the fallback set used when no gitleaks.toml is supplied.
var builtinRules = []struct {
	id, pattern string
	keywords    []string
}{
	{"openai-key", `sk-(?:proj-)?[A-Za-z0-9_-]{20,}`, []string{"sk-"}},
	{"aws-access-key", `AKIA[0-9A-Z]{16}`, []string{"akia"}},
	{"github-token", `gh[pousr]_[A-Za-z0-9]{36,}`, []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}},
	{"google-api-key", `AIza[0-9A-Za-z_-]{35}`, []string{"aiza"}},
	{"slack-token", `xox[baprs]-[0-9A-Za-z-]{10,}`, []string{"xox"}},
	{"jwt", `eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`, []string{"eyj"}},
	{"private-key", `-----BEGIN[A-Z ]*PRIVATE KEY-----`, []string{"private key"}},
}

// LoadRules compiles a gitleaks rule document. An empty document (or one whose
// rules all fail to compile) falls back to the built-in rule set, matching the
// behaviour of the upstream privacy-filter library. skipped counts rules whose
// regex is not valid RE2.
func LoadRules(document []byte, disabled []string) (rules []Rule, skipped int, err error) {
	if len(strings.TrimSpace(string(document))) == 0 {
		return builtins(disabled), 0, nil
	}
	var cfg tomlConfig
	if _, errDecode := toml.Decode(string(document), &cfg); errDecode != nil {
		return nil, 0, fmt.Errorf("parse gitleaks rules: %w", errDecode)
	}
	drop := disabledSet(disabled)
	for _, raw := range cfg.Rules {
		if raw.Regex == "" {
			continue
		}
		if drop[strings.ToLower(strings.TrimSpace(raw.ID))] {
			continue
		}
		re, errCompile := regexp.Compile(raw.Regex)
		if errCompile != nil {
			skipped++
			continue
		}
		keywords := make([]string, 0, len(raw.Keywords))
		for _, keyword := range raw.Keywords {
			if keyword == "" {
				continue
			}
			keywords = append(keywords, strings.ToLower(keyword))
		}
		rules = append(rules, Rule{
			ID:          raw.ID,
			Re:          re,
			Keywords:    keywords,
			Entropy:     raw.Entropy,
			SecretGroup: raw.SecretGroup,
		})
	}
	if len(rules) == 0 {
		return builtins(disabled), skipped, nil
	}
	return rules, skipped, nil
}

func builtins(disabled []string) []Rule {
	drop := disabledSet(disabled)
	out := make([]Rule, 0, len(builtinRules))
	for _, b := range builtinRules {
		if drop[b.id] {
			continue
		}
		out = append(out, Rule{
			ID:       b.id,
			Re:       regexp.MustCompile(b.pattern),
			Keywords: b.keywords,
		})
	}
	return out
}

func disabledSet(disabled []string) map[string]bool {
	if len(disabled) == 0 {
		return nil
	}
	set := make(map[string]bool, len(disabled))
	for _, id := range disabled {
		if trimmed := strings.ToLower(strings.TrimSpace(id)); trimmed != "" {
			set[trimmed] = true
		}
	}
	return set
}
