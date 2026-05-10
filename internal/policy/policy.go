package policy

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/youwantitdarker28/Command-Guard/internal/analyzer"
)

type Action string

const (
	ActionAllow           Action = "allow"
	ActionWarn            Action = "warn"
	ActionRequireApproval Action = "require_approval"
	ActionBlock           Action = "block"
)

type Config struct {
	Version int
	Mode    string
	Rules   []Rule
	Audit   Audit
}
type Rule struct {
	Match, Category string
	Action          Action
	ReasonRequired  bool
}
type Audit struct {
	Enabled bool
	Path    string
}
type Evaluation struct {
	Category string
	Action   Action
	Matched  *Rule
}
type Record struct {
	Timestamp    string `json:"timestamp"`
	Command      string `json:"command"`
	Risk         string `json:"risk"`
	Category     string `json:"category"`
	PolicyAction Action `json:"policy_action"`
	Decision     string `json:"decision"`
}

func Load() (*Config, error) {
	cfg, _, err := LoadFromCandidates("./digest.policy.yaml", "~/.digest/policy.yaml")
	return cfg, err
}

func LoadFromCandidates(paths ...string) (*Config, string, error) {
	for _, p := range paths {
		expanded := expandPath(p)
		b, err := os.ReadFile(expanded)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, "", err
		}
		cfg, err := Parse(b)
		if err != nil {
			return nil, "", fmt.Errorf("parse policy %s: %w", expanded, err)
		}
		return cfg, expanded, nil
	}
	return nil, "", nil
}

func Parse(content []byte) (*Config, error) {
	cfg := &Config{}
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	inRules, inAudit := false, false
	var cur *Rule
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case line == "rules:":
			inRules, inAudit = true, false
			continue
		case line == "audit:":
			inRules, inAudit = false, true
			if cur != nil {
				cfg.Rules = append(cfg.Rules, *cur)
				cur = nil
			}
			continue
		}
		if inRules {
			if strings.HasPrefix(line, "-") {
				if cur != nil {
					cfg.Rules = append(cfg.Rules, *cur)
				}
				cur = &Rule{}
				line = strings.TrimSpace(strings.TrimPrefix(line, "-"))
				if line == "" {
					continue
				}
			}
			if cur == nil {
				continue
			}
			k, v, ok := kv(line)
			if !ok {
				continue
			}
			switch k {
			case "match":
				cur.Match = v
			case "category":
				cur.Category = v
			case "action":
				cur.Action = Action(v)
			case "reason_required":
				cur.ReasonRequired = (v == "true")
			}
			continue
		}
		if inAudit {
			k, v, ok := kv(line)
			if !ok {
				continue
			}
			switch k {
			case "enabled":
				cfg.Audit.Enabled = (v == "true")
			case "path":
				cfg.Audit.Path = v
			}
			continue
		}
		k, v, ok := kv(line)
		if !ok {
			continue
		}
		switch k {
		case "version":
			n, _ := strconv.Atoi(v)
			cfg.Version = n
		case "mode":
			cfg.Mode = v
		}
	}
	if cur != nil {
		cfg.Rules = append(cfg.Rules, *cur)
	}
	for i, r := range cfg.Rules {
		if r.Match == "" && r.Category == "" {
			return nil, fmt.Errorf("rule %d must define match or category", i)
		}

		if r.Action != ActionAllow && r.Action != ActionWarn && r.Action != ActionRequireApproval && r.Action != ActionBlock {
			return nil, fmt.Errorf("invalid action %q", r.Action)
		}
	}
	return cfg, scanner.Err()
}

func parseBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "yes", "on", "1":
		return true
	default:
		return false
	}
}

func kv(line string) (string, string, bool) {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	k := strings.TrimSpace(parts[0])
	v := strings.TrimSpace(parts[1])
	v = strings.Trim(v, `"'`)
	return k, v, true
}

func Evaluate(cfg *Config, analysis analyzer.Result) Evaluation {
	category := DeriveCategory(analysis)
	if cfg == nil {
		return Evaluation{Category: category, Action: ActionWarn}
	}
	cmd := strings.ToLower(analysis.Command)
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if r.Match != "" && strings.Contains(cmd, strings.ToLower(r.Match)) {
			return Evaluation{Category: category, Action: r.Action, Matched: r}
		}
		if r.Category != "" && r.Category == category {
			return Evaluation{Category: category, Action: r.Action, Matched: r}
		}
	}
	return Evaluation{Category: category, Action: ActionWarn}
}

func DeriveCategory(r analyzer.Result) string {
	cmd := strings.ToLower(r.Command)
	base := strings.ToLower(r.CommandBase)
	if strings.Contains(cmd, "git push --force") || strings.Contains(cmd, "git push -f") || strings.Contains(cmd, "git reset --hard") {
		return "git_history_rewrite"
	}
	if strings.Contains(cmd, "git clean -f") || strings.Contains(cmd, "git clean --force") {
		return "destructive"
	}
	if base == "sudo" || strings.HasPrefix(cmd, "sudo ") {
		return "privilege_escalation"
	}
	if r.IsPackageInstall {
		return "package_install"
	}
	if base == "curl" || base == "wget" || strings.Contains(cmd, "http://") || strings.Contains(cmd, "https://") {
		return "network"
	}
	if base == "rm" || base == "shred" || base == "dd" || base == "mkfs" || base == "wipefs" || base == "fdisk" || strings.Contains(cmd, "--force") || strings.Contains(cmd, " -f") {
		return "destructive"
	}
	if r.Risk == analyzer.RiskLow {
		return "read_only"
	}
	return "unknown"
}

func AppendAudit(cfg *Config, record Record) error {
	if cfg == nil || !cfg.Audit.Enabled {
		return nil
	}
	path := expandPath(cfg.Audit.Path)
	if path == "" {
		path = expandPath("~/.digest/audit.log")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if record.Timestamp == "" {
		record.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return err
	}
	_, err = f.Write(append(payload, '\n'))
	return err
}

func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}
