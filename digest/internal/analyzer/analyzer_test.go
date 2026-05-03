package analyzer_test

import (
	"strings"
	"testing"

	"github.com/digest/internal/analyzer"
)

// ── Package install detection ─────────────────────────────────────────────────

func TestDetectPackageInstall(t *testing.T) {
	t.Parallel()

	tests := []struct {
		args        []string
		wantInstall bool
		wantPkgs    []string
		wantManager string
	}{
		// npm
		{[]string{"npm", "install", "express", "lodash"}, true, []string{"express", "lodash"}, "npm"},
		{[]string{"npm", "i", "-D", "typescript", "--save-exact", "prettier"}, true, []string{"typescript", "prettier"}, "npm"},
		{[]string{"npm", "install"}, true, nil, "npm"},
		{[]string{"npm", "run", "build"}, false, nil, ""},
		{[]string{"npm", "publish"}, false, nil, ""},

		// go
		{[]string{"go", "get", "github.com/charmbracelet/bubbletea"}, true, []string{"github.com/charmbracelet/bubbletea"}, "go"},
		{[]string{"go", "get", "-u", "github.com/some/pkg@v1.2.3"}, true, []string{"github.com/some/pkg@v1.2.3"}, "go"},
		{[]string{"go", "install", "golang.org/x/tools/cmd/goimports@latest"}, true, []string{"golang.org/x/tools/cmd/goimports@latest"}, "go"},
		{[]string{"go", "build", "."}, false, nil, ""},
		{[]string{"go", "run", "main.go"}, false, nil, ""},

		// pip
		{[]string{"pip", "install", "requests", "flask"}, true, []string{"requests", "flask"}, "pip"},
		{[]string{"pip", "install", "--upgrade", "requests"}, true, []string{"requests"}, "pip"},
		{[]string{"pip", "install", "-r", "requirements.txt"}, true, nil, "pip"},
		{[]string{"pip3", "install", "numpy"}, true, []string{"numpy"}, "pip3"},

		// cargo
		{[]string{"cargo", "add", "serde"}, true, []string{"serde"}, "cargo"},
		{[]string{"cargo", "add", "serde", "--features", "derive"}, true, []string{"serde"}, "cargo"},
		{[]string{"cargo", "install", "ripgrep"}, true, []string{"ripgrep"}, "cargo"},

		// yarn
		{[]string{"yarn", "add", "react", "react-dom"}, true, []string{"react", "react-dom"}, "yarn"},
		{[]string{"yarn", "add", "-D", "@types/react"}, true, []string{"@types/react"}, "yarn"},

		// pnpm
		{[]string{"pnpm", "add", "vite", "-D"}, true, []string{"vite"}, "pnpm"},
		{[]string{"pnpm", "install"}, true, nil, "pnpm"},

		// brew
		{[]string{"brew", "install", "ffmpeg", "jq"}, true, []string{"ffmpeg", "jq"}, "brew"},

		// apt / apt-get
		{[]string{"apt", "install", "-y", "curl", "wget"}, true, []string{"curl", "wget"}, "apt"},
		{[]string{"apt-get", "install", "git"}, true, []string{"git"}, "apt-get"},

		// dotnet
		{[]string{"dotnet", "add", "package", "Newtonsoft.Json"}, true, []string{"Newtonsoft.Json"}, "dotnet"},

		// gem
		{[]string{"gem", "install", "rails"}, true, []string{"rails"}, "gem"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			t.Parallel()
			got := analyzer.Analyze(tt.args)

			if got.IsPackageInstall != tt.wantInstall {
				t.Errorf("IsPackageInstall = %v, want %v", got.IsPackageInstall, tt.wantInstall)
				return
			}
			if !tt.wantInstall {
				return
			}
			if got.PackageManager != tt.wantManager {
				t.Errorf("PackageManager = %q, want %q", got.PackageManager, tt.wantManager)
			}
			for _, want := range tt.wantPkgs {
				found := false
				for _, p := range got.Packages {
					if p == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("package %q not found in %v", want, got.Packages)
				}
			}
		})
	}
}

// ── Risk classification ───────────────────────────────────────────────────────

func TestRiskClassification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		args     []string
		wantRisk analyzer.RiskLevel
	}{
		// Explicitly high risk
		{[]string{"rm", "-rf", "./tmp"}, analyzer.RiskHigh},
		{[]string{"sudo", "apt", "install", "curl"}, analyzer.RiskHigh},
		{[]string{"git", "push", "--force"}, analyzer.RiskHigh},
		{[]string{"git", "push", "-f"}, analyzer.RiskHigh},
		{[]string{"git", "push", "--force-with-lease"}, analyzer.RiskHigh},
		{[]string{"git", "reset", "--hard"}, analyzer.RiskHigh},
		{[]string{"dd", "if=/dev/urandom", "of=/dev/sda"}, analyzer.RiskHigh},
		{[]string{"chmod", "777", "/etc/passwd"}, analyzer.RiskHigh},
		{[]string{"shred", "-u", "secrets.txt"}, analyzer.RiskHigh},

		// Dangerous substring patterns
		{[]string{"bash", "-c", "cat /dev/urandom > /dev/sda"}, analyzer.RiskHigh},

		// Low risk
		{[]string{"ls", "-la"}, analyzer.RiskLow},
		{[]string{"cat", "README.md"}, analyzer.RiskLow},
		{[]string{"grep", "-r", "TODO", "."}, analyzer.RiskLow},
		{[]string{"git", "log", "--oneline"}, analyzer.RiskLow},

		// Medium risk — package installs
		{[]string{"npm", "install", "express"}, analyzer.RiskMedium},
		{[]string{"pip", "install", "flask"}, analyzer.RiskMedium},
		{[]string{"go", "get", "github.com/foo/bar"}, analyzer.RiskMedium},
		{[]string{"cargo", "add", "serde"}, analyzer.RiskMedium},
		{[]string{"brew", "install", "ffmpeg"}, analyzer.RiskMedium},

		// Medium risk — general
		{[]string{"mv", "a.txt", "b.txt"}, analyzer.RiskMedium},
		{[]string{"docker", "run", "-it", "ubuntu"}, analyzer.RiskMedium},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			t.Parallel()
			got := analyzer.Analyze(tt.args)
			if got.Risk != tt.wantRisk {
				t.Errorf("Risk = %s, want %s\n  ThreatSummary: %s", got.Risk, tt.wantRisk, got.ThreatSummary)
			}
		})
	}
}

// ── Result fields ─────────────────────────────────────────────────────────────

func TestResultFields(t *testing.T) {
	r := analyzer.Analyze([]string{"rm", "-rf", "./tmp"})
	if r.Command != "rm -rf ./tmp" {
		t.Errorf("Command = %q", r.Command)
	}
	if r.CommandBase != "rm" {
		t.Errorf("CommandBase = %q", r.CommandBase)
	}
	if r.ThreatSummary == "" {
		t.Error("ThreatSummary is empty")
	}
	if r.PromptTip == "" {
		t.Error("PromptTip is empty")
	}
}

func TestEmptyArgs(t *testing.T) {
	r := analyzer.Analyze(nil)
	if r.Risk != analyzer.RiskMedium {
		t.Errorf("empty args: Risk = %s, want MEDIUM", r.Risk)
	}
}
