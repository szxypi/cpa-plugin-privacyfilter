package scan

import (
	"strings"
	"testing"
)

// gateSamples adds spacing / separator edge cases on top of the parity corpus,
// because the prescan gates are only safe if they are true necessary
// conditions of the regexes they replace.
func gateSamples(t testing.TB) []string {
	samples := parityCorpus(t)
	return append(samples,
		"token   :   hunter2secretvalue",
		"token\n\n\t: hunter2secretvalue",
		"API_KEY = AbCdEfGh12345678",
		"api key: AbCdEfGh12345678",
		"api-key:AbCdEfGh12345678",
		"apikey=AbCdEfGh12345678",
		"我的口令为：hunter2secretvalue",
		"密钥 = AbCdEfGh12345678",
		"ip 1.2.3.4 and 255.255.255.255 and 1.2.3 and 12.881",
		"版本 1.2.3.4 后面",
		"a"+strings.Repeat("b", 19),
		strings.Repeat("c", 20),
		strings.Repeat("d", 25)+"!"+strings.Repeat("e", 30),
	)
}

// TestPrescanTokenRunsMatchRegex proves the prescan reproduces
// reEntropyToken.FindAllStringIndex exactly, which is why the regex is gone.
func TestPrescanTokenRunsMatchRegex(t *testing.T) {
	s := newTestScanner(t)
	patHit := make([]bool, s.patterns)
	for _, sample := range gateSamples(t) {
		clear(patHit)
		sig := s.prescan(sample, patHit, nil)
		want := reEntropyToken.FindAllStringIndex(sample, -1)
		if len(want) != len(sig.tokenRuns) {
			t.Fatalf("run count %d != regex %d for %q", len(sig.tokenRuns), len(want), sample)
		}
		for i, m := range want {
			if sig.tokenRuns[i].start != m[0] || sig.tokenRuns[i].end != m[1] {
				t.Fatalf("run %d = [%d,%d), regex = [%d,%d) for %q",
					i, sig.tokenRuns[i].start, sig.tokenRuns[i].end, m[0], m[1], sample)
			}
		}
	}
}

// TestPrescanGatesAreNecessaryConditions checks that a closed gate always
// means the gated regex has nothing to find.
func TestPrescanGatesAreNecessaryConditions(t *testing.T) {
	s := newTestScanner(t)
	patHit := make([]bool, s.patterns)
	for _, sample := range gateSamples(t) {
		clear(patHit)
		sig := s.prescan(sample, patHit, nil)

		if !sig.hasAt && reEmail.MatchString(sample) {
			t.Fatalf("email gate closed but regex matches: %q", sample)
		}
		if !sig.hasIPv4 && reIPv4.MatchString(sample) {
			t.Fatalf("ipv4 gate closed but regex matches: %q", sample)
		}
		if !sig.hasContext && reContextSecret.MatchString(sample) {
			t.Fatalf("context gate closed but regex matches: %q", sample)
		}
		if sig.maxDigitRun < 11 && rePhoneCN.MatchString(sample) {
			t.Fatalf("phone gate closed but regex matches: %q", sample)
		}
		if sig.maxDigitRun < 13 && reBankCard.MatchString(sample) {
			t.Fatalf("bank card gate closed but regex matches: %q", sample)
		}
		if sig.maxDigitRun < 17 && reIDCard.MatchString(sample) {
			t.Fatalf("id card gate closed but regex matches: %q", sample)
		}
		for i := range s.rules {
			if s.ruleApplies(i, patHit) {
				continue
			}
			if s.rules[i].Re.MatchString(sample) {
				t.Fatalf("rule %s gated off but matches: %q", s.rules[i].ID, sample)
			}
		}
	}
}
