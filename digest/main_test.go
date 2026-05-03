package main

import (
	"strings"
	"testing"
)

func TestDetectPackageInstall(t *testing.T) {
	tests := []struct {
		args        []string
		wantInstall bool
		wantPkgs    []string
		wantManager string
	}{
		// npm
		{[]string{"npm", "install", "express", "lodash"}, true, []string{"express", "lodash"}, "npm"},
		{[]string{"npm", "i", "-D", "typescript", "--save-exact", "prettier"}, true, []string{"typescript", "prettier"}, "npm"},
		{[]string{"npm", "install"}, true, []string{}, "npm"},
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
		{[]string{"pip", "install", "-r", "requirements.txt"}, true, []string{}, "pip"},
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
		{[]string{"pnpm", "install"}, true, []string{}, "pnpm"},

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
		cmd := strings.Join(tt.args, " ")
		isInstall, manager, pkgs := detectPackageInstall(strings.ToLower(filepathBase(tt.args[0])), tt.args)

		if isInstall != tt.wantInstall {
			t.Errorf("[%s] isInstall: got %v, want %v", cmd, isInstall, tt.wantInstall)
			continue
		}
		if !tt.wantInstall {
			continue
		}
		if manager != tt.wantManager {
			t.Errorf("[%s] manager: got %q, want %q", cmd, manager, tt.wantManager)
		}
		if len(tt.wantPkgs) == 0 && len(pkgs) != 0 {
			t.Errorf("[%s] expected empty packages, got %v", cmd, pkgs)
		}
		for _, want := range tt.wantPkgs {
			found := false
			for _, got := range pkgs {
				if got == want {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("[%s] missing expected package %q in %v", cmd, want, pkgs)
			}
		}
	}
}

func TestAnalyzeCommandRisk(t *testing.T) {
	tests := []struct {
		args     []string
		wantRisk RiskLevel
	}{
		{[]string{"rm", "-rf", "./tmp"}, RiskHigh},
		{[]string{"sudo", "apt", "install", "curl"}, RiskHigh},
		{[]string{"git", "push", "--force"}, RiskHigh},
		{[]string{"git", "push", "-f"}, RiskHigh},
		{[]string{"ls", "-la"}, RiskLow},
		{[]string{"cat", "README.md"}, RiskLow},
		{[]string{"npm", "install", "express"}, RiskMedium},
		{[]string{"pip", "install", "flask"}, RiskMedium},
		{[]string{"go", "get", "github.com/foo/bar"}, RiskMedium},
		{[]string{"mv", "a.txt", "b.txt"}, RiskMedium},
	}

	for _, tt := range tests {
		cmd := strings.Join(tt.args, " ")
		a := analyzeCommand(tt.args)
		if a.Risk != tt.wantRisk {
			t.Errorf("[%s] risk: got %s, want %s", cmd, a.Risk, tt.wantRisk)
		}
	}
}
