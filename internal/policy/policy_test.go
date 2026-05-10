package policy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/youwantitdarker28/Command-Guard/internal/analyzer"
	"github.com/youwantitdarker28/Command-Guard/internal/policy"
)

func TestParseValidYAML(t *testing.T) {
	cfg, err := policy.Parse([]byte(`version: 1
rules:
  - match: "rm -rf"
    action: require_approval
`))
	if err != nil || cfg.Version != 1 || len(cfg.Rules) != 1 {
		t.Fatalf("parse failed: %v", err)
	}
}

func TestLoadFromCandidatesLocalWins(t *testing.T) {
	dir := t.TempDir()
	global := filepath.Join(dir, "global.yaml")
	local := filepath.Join(dir, "local.yaml")
	_ = os.WriteFile(global, []byte("version: 1\nrules:\n  - category: read_only\n    action: allow\n"), 0o644)
	_ = os.WriteFile(local, []byte("version: 1\nrules:\n  - category: read_only\n    action: block\n"), 0o644)

	cfg, path, err := policy.LoadFromCandidates(local, global)
	if err != nil || cfg == nil {
		t.Fatalf("load failed: %v", err)
	}
	if path != local || cfg.Rules[0].Action != policy.ActionBlock {
		t.Fatalf("unexpected precedence: path=%s action=%s", path, cfg.Rules[0].Action)
	}
}

func TestFirstMatchWins(t *testing.T) {
	cfg, _ := policy.Parse([]byte(`version: 1
rules:
  - category: read_only
    action: warn
  - category: read_only
    action: block
`))
	a := analyzer.Analyze([]string{"ls", "-la"})
	eval := policy.Evaluate(cfg, a)
	if eval.Action != policy.ActionWarn {
		t.Fatalf("got %s", eval.Action)
	}
}

func TestSubstringAndCategoryRuleMatch(t *testing.T) {
	cfg, _ := policy.Parse([]byte(`version: 1
rules:
  - match: "git push --force"
    action: block
  - category: read_only
    action: allow
`))
	eval := policy.Evaluate(cfg, analyzer.Analyze([]string{"git", "push", "--force"}))
	if eval.Action != policy.ActionBlock {
		t.Fatalf("expected block")
	}
	eval = policy.Evaluate(cfg, analyzer.Analyze([]string{"ls"}))
	if eval.Action != policy.ActionAllow {
		t.Fatalf("expected allow")
	}
}

func TestAuditJSONLWrite(t *testing.T) {
	dir := t.TempDir()
	cfg := &policy.Config{Audit: policy.Audit{Enabled: true, Path: filepath.Join(dir, "audit.log")}}
	err := policy.AppendAudit(cfg, policy.Record{Command: "rm -rf ./dist", Risk: "HIGH", Category: "destructive", PolicyAction: policy.ActionRequireApproval, Decision: "approved"})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(cfg.Audit.Path)
	line := strings.TrimSpace(string(data))
	for _, token := range []string{"\"command\":\"rm -rf ./dist\"", "\"decision\":\"approved\"", "\"policy_action\":\"require_approval\""} {
		if !strings.Contains(line, token) {
			t.Fatalf("missing token %s in %s", token, line)
		}
	}
}

func TestNoPolicyDefaultsToWarn(t *testing.T) {
	eval := policy.Evaluate(nil, analyzer.Analyze([]string{"ls"}))
	if eval.Action != policy.ActionWarn {
		t.Fatalf("got %s", eval.Action)
	}
}
