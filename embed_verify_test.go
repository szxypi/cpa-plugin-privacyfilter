package main

import (
	"testing"
)

// TestNewScanner_UsesEmbeddedRules simulates a store install: an empty plugin
// directory with no rules/gitleaks.toml sidecar. newScanner must still load the
// embedded rules, proving the plugin works without a sidecar file.
func TestNewScanner_UsesEmbeddedRules(t *testing.T) {
	emptyDir := t.TempDir()

	scanner, err := newScanner(emptyDir, defaultConfig())
	if err != nil {
		t.Fatalf("newScanner() with embedded rules error = %v", err)
	}
	rules, _ := scanner.Stats()
	if rules < 100 {
		t.Fatalf("expected the embedded gitleaks set, got %d rules", rules)
	}
	t.Logf("loaded %d embedded rules without a sidecar file", rules)

	if got := scanner.Redact("token " + sampleToken); !got.Hit {
		t.Fatal("embedded rules did not detect a github token")
	}
}
