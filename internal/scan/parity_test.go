package scan

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"

	upstream "privacyfilter/filter"
)

const rulesPath = "../../rules/gitleaks.toml"

func newTestScanner(t testing.TB, disabled ...string) *Scanner {
	t.Helper()
	document, err := os.ReadFile(rulesPath)
	if err != nil {
		t.Fatalf("read rules: %v", err)
	}
	rules, skipped, err := LoadRules(document, disabled)
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	return New(rules, skipped)
}

func newUpstream(t testing.TB) *upstream.Filter {
	t.Helper()
	f, err := upstream.New(rulesPath)
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}
	return f
}

// parityCorpus is the shared sample set: upstream's own regression fixtures,
// hand-written samples for every detector, and pseudo-random noise.
func parityCorpus(t testing.TB) []string {
	t.Helper()
	var samples []string

	raw, err := os.ReadFile("testdata/cases.json")
	if err != nil {
		t.Fatalf("read cases.json: %v", err)
	}
	var cases []struct {
		Input string `json:"input"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases.json: %v", err)
	}
	for _, c := range cases {
		samples = append(samples, c.Input)
	}

	samples = append(samples,
		"",
		"hello world",
		"my email is test@example.com",
		"contact: Dev.Lead+tag@sub.example.co.uk please",
		"ssh deploy@10.0.0.4 -i ~/.ssh/id_ed25519",
		"git@github.com:rheodev/cpa-plugin-privacyfilter.git",
		"my phone is 13800138000 and my backup is +86 13911112222",
		"身份证 110101199003078534 银行卡 4111111111111111",
		"server at 10.20.30.41:8317 replied 200",
		"export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"github token ghp_016C7869C1AE4A4EBFDEE0A1CBF9C8B0EF37 rotate it",
		"OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl012mno345pqr",
		"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		"我的密码是 hunter2Password!",
		"api_key: \"REPLACE_ME\"",
		"api_key: ${MY_TOKEN}",
		"order_id=8f7c1a9e4b2d6f0a3c5e7b9d1f",
		"digest registry.io/img@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		"docker run -e TOKEN=abcdefghijklmnopqrstuvwxyz012345 image:tag",
		"a normal sentence about the access key policy in our documentation",
		"password: 12345678901234567890, token: aaaaaaaaaaaaaaaaaaaaaa",
		strings.Repeat("no secrets here, only prose about design and layout. ", 200),
		strings.Repeat("func main() { fmt.Println(\"api token key secret\") }\n", 200),
	)

	rng := rand.New(rand.NewSource(20260910))
	alphabet := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=_-.:@ \n\t\"'{}[],;"
	words := []string{"token", "api_key", "password", "secret", "AKIA", "ghp_", "sk-", "http://", "密钥", "= ", ": "}
	for i := 0; i < 400; i++ {
		var b strings.Builder
		n := rng.Intn(300) + 1
		for j := 0; j < n; j++ {
			if rng.Intn(12) == 0 {
				b.WriteString(words[rng.Intn(len(words))])
				continue
			}
			b.WriteByte(alphabet[rng.Intn(len(alphabet))])
		}
		samples = append(samples, b.String())
	}
	return samples
}

// TestParityWithUpstream is the safety net for the ported detection code: for
// every sample the fast scanner must produce byte-identical output to
// github.com/packyme/privacy-filter.
func TestParityWithUpstream(t *testing.T) {
	scanner := newTestScanner(t)
	reference := newUpstream(t)
	for i, sample := range parityCorpus(t) {
		want := reference.Redact(sample)
		got := scanner.Redact(sample)
		if got.Hit != want.Hit || got.Count != want.Count || got.Redacted != want.Redacted {
			t.Fatalf("sample %d diverged\n input : %q\n want  : hit=%v count=%d %q\n got   : hit=%v count=%d %q",
				i, sample, want.Hit, want.Count, want.Redacted, got.Hit, got.Count, got.Redacted)
		}
	}
}

// TestParityOnLargeBody exercises the prescan on a body the size of a real
// coding-agent turn.
func TestParityOnLargeBody(t *testing.T) {
	scanner := newTestScanner(t)
	reference := newUpstream(t)
	var b strings.Builder
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&b, "line %d: func handle(ctx context.Context) error { return store.Put(ctx, key) } // token\n", i)
		if i%37 == 0 {
			b.WriteString("export GITHUB_TOKEN=ghp_016C7869C1AE4A4EBFDEE0A1CBF9C8B0EF37\n")
		}
		if i%53 == 0 {
			b.WriteString("reach me at ops.team@example.com or 13800138000\n")
		}
	}
	text := b.String()
	want := reference.Redact(text)
	got := scanner.Redact(text)
	if got.Redacted != want.Redacted || got.Count != want.Count {
		t.Fatalf("large body diverged: want count=%d got count=%d", want.Count, got.Count)
	}
	if !got.Hit {
		t.Fatal("expected hits in the large body")
	}
}

func TestBuiltinRulesParity(t *testing.T) {
	rules, skipped, err := LoadRules(nil, nil)
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	scanner := New(rules, skipped)
	reference, err := upstream.New("")
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}
	for i, sample := range parityCorpus(t) {
		want := reference.Redact(sample)
		got := scanner.Redact(sample)
		if got.Redacted != want.Redacted || got.Hit != want.Hit {
			t.Fatalf("builtin sample %d diverged\n input: %q\n want : %q\n got  : %q", i, sample, want.Redacted, got.Redacted)
		}
	}
}

func TestDisableRulesDropsRule(t *testing.T) {
	full := newTestScanner(t)
	trimmed := newTestScanner(t, "generic-api-key")
	fullCount, _ := full.Stats()
	trimmedCount, _ := trimmed.Stats()
	if trimmedCount != fullCount-1 {
		t.Fatalf("disable_rules did not drop exactly one rule: %d -> %d", fullCount, trimmedCount)
	}
	for _, id := range trimmed.RuleIDs() {
		if id == "generic-api-key" {
			t.Fatal("generic-api-key still loaded")
		}
	}
}

func TestLabelsCounted(t *testing.T) {
	scanner := newTestScanner(t)
	got := scanner.Redact("mail me at a@b.com or call 13800138000")
	if !got.Hit || got.Labels["[邮箱]"] != 1 || got.Labels["[电话]"] != 1 {
		t.Fatalf("unexpected labels: %+v (%q)", got.Labels, got.Redacted)
	}
}

func TestConcurrentRedact(t *testing.T) {
	scanner := newTestScanner(t)
	samples := parityCorpus(t)
	reference := newUpstream(t)
	want := make([]string, len(samples))
	for i, s := range samples {
		want[i] = reference.Redact(s).Redacted
	}
	done := make(chan struct{})
	for w := 0; w < 8; w++ {
		go func(offset int) {
			defer func() { done <- struct{}{} }()
			for i := range samples {
				idx := (i + offset) % len(samples)
				if got := scanner.Redact(samples[idx]).Redacted; got != want[idx] {
					t.Errorf("concurrent mismatch at %d", idx)
					return
				}
			}
		}(w * 13)
	}
	for w := 0; w < 8; w++ {
		<-done
	}
}
