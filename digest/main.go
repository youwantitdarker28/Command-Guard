package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ── Risk levels ───────────────────────────────────────────────────────────────

type RiskLevel int

const (
	RiskLow RiskLevel = iota
	RiskMedium
	RiskHigh
)

func (r RiskLevel) String() string {
	switch r {
	case RiskLow:
		return "LOW"
	case RiskMedium:
		return "MEDIUM"
	case RiskHigh:
		return "HIGH"
	default:
		return "UNKNOWN"
	}
}

// ── Command analysis result ───────────────────────────────────────────────────

type CommandAnalysis struct {
	Command          string
	RawArgs          []string
	Risk             RiskLevel
	Warning          string
	PromptTip        string
	CommandBase      string
	IsPackageInstall bool
	Packages         []string
	PackageManager   string
}

// ── Risk tables ───────────────────────────────────────────────────────────────

var highRiskPatterns = map[string]string{
	"rm":       "Permanently removes files or directories — cannot be undone.",
	"sudo":     "Runs commands with root (superuser) privileges — full system access.",
	"chmod":    "Changes file permissions — incorrect use can lock you out of files.",
	"chown":    "Changes file ownership — can revoke your own access to files.",
	"dd":       "Writes raw data to disk — one typo can wipe an entire drive.",
	"mkfs":     "Formats a filesystem — erases all data on the target device.",
	"fdisk":    "Manages disk partitions — destructive changes take immediate effect.",
	"shred":    "Overwrites files to make them unrecoverable — irreversible.",
	"truncate": "Shrinks or empties files — data is permanently lost.",
	"kill":     "Sends signals to processes — can terminate critical system services.",
	"killall":  "Kills all processes by name — wide blast radius.",
	"pkill":    "Kills processes matching a pattern — can hit unintended targets.",
}

var highRiskFlags = map[string][]string{
	"git":  {"push -f", "push --force", "push --force-with-lease", "reset --hard"},
	"npm":  {"publish"},
	"yarn": {"publish"},
	"curl": {"-X DELETE", "--request DELETE"},
}

var lowRiskCommands = map[string]string{
	"ls":       "Lists files and directories in the current path.",
	"cat":      "Reads and displays the contents of a file.",
	"echo":     "Prints text to the terminal output.",
	"pwd":      "Prints the current working directory path.",
	"whoami":   "Shows the current logged-in username.",
	"date":     "Displays the current date and time.",
	"cal":      "Shows a calendar for the current month.",
	"which":    "Finds the path of an executable command.",
	"type":     "Describes how a command will be interpreted.",
	"file":     "Determines the type of a file.",
	"wc":       "Counts lines, words, and characters in a file.",
	"head":     "Shows the first lines of a file.",
	"tail":     "Shows the last lines of a file.",
	"grep":     "Searches for patterns within text or files.",
	"find":     "Searches for files and directories.",
	"sort":     "Sorts lines of text input.",
	"uniq":     "Filters out duplicate adjacent lines.",
	"diff":     "Compares two files and shows their differences.",
	"man":      "Opens the manual page for a command.",
	"help":     "Shows usage information for a command.",
	"env":      "Lists current environment variables.",
	"printenv": "Prints the value of an environment variable.",
	"uname":    "Shows system information (OS, kernel version).",
	"uptime":   "Shows how long the system has been running.",
	"df":       "Displays disk space usage for filesystems.",
	"du":       "Shows disk usage for files and directories.",
	"ps":       "Lists currently running processes.",
	"top":      "Shows a live view of system resource usage.",
	"htop":     "An enhanced interactive process viewer.",
	"ping":     "Checks network connectivity to a host.",
	"curl":     "Transfers data from or to a network server.",
	"wget":     "Downloads files from the internet.",
	"git":      "Distributed version control system for code.",
	"go":       "Builds, tests, and runs Go programs.",
	"node":     "Executes JavaScript programs with Node.js.",
	"python":   "Executes Python programs or scripts.",
	"python3":  "Executes Python 3 programs or scripts.",
}

var mediumRiskTips = map[string]string{
	"mv":      "Moves or renames files — the original location will be empty after this.",
	"cp":      "Copies files or directories to a new location.",
	"mkdir":   "Creates a new directory at the specified path.",
	"touch":   "Creates an empty file or updates a file's timestamp.",
	"tar":     "Archives or extracts files — check flags before running.",
	"zip":     "Compresses files into a ZIP archive.",
	"unzip":   "Extracts files from a ZIP archive.",
	"apt":     "Manages packages on Debian-based Linux systems.",
	"apt-get": "Installs, updates, or removes system packages.",
	"brew":    "macOS package manager — installs and manages software.",
	"pip":     "Installs Python packages — runs code from the internet.",
	"pip3":    "Installs Python 3 packages — runs code from the internet.",
	"npm":     "Installs JavaScript packages and runs scripts.",
	"yarn":    "JavaScript package manager — installs dependencies.",
	"pnpm":    "Fast JavaScript package manager.",
	"docker":  "Runs and manages containerized applications.",
	"ssh":     "Opens a secure shell connection to a remote machine.",
	"scp":     "Securely copies files between local and remote machines.",
	"rsync":   "Syncs files between locations — can overwrite destination.",
	"make":    "Runs build tasks defined in a Makefile.",
	"cron":    "Schedules recurring tasks on the system.",
	"crontab": "Edits the cron job schedule for your user.",
	"export":  "Sets an environment variable for the current session.",
	"source":  "Runs a script in the current shell environment.",
	"bash":    "Starts a new Bash shell or runs a shell script.",
	"sh":      "Runs a shell script using the POSIX shell.",
	"zsh":     "Starts the Zsh shell or runs a Zsh script.",
}

// ── Package manager detection ─────────────────────────────────────────────────

// pkgManagerDef describes how to detect an install invocation for a given tool.
type pkgManagerDef struct {
	// display name shown in the UI
	label string
	// subcommands that trigger an install (e.g. "install", "add", "get")
	installSubs []string
	// flags that carry a value and must be skipped together with their next token
	valueFlags []string
	// flags whose argument is attached (e.g. "--target=foo") — prefix match
	attachedFlagPrefixes []string
	// pure boolean flags to skip (no value consumed)
	skipFlags []string
}

var packageManagers = map[string]pkgManagerDef{
	"npm": {
		label:       "npm",
		installSubs: []string{"install", "i", "add", "isntall"},
		valueFlags:  []string{"--workspace", "-w", "--tag", "--otp", "--registry"},
		skipFlags:   []string{"-g", "--global", "--save", "--save-dev", "-D", "--save-exact", "-E", "--save-optional", "-O", "--no-save", "-P", "--save-prod", "--legacy-peer-deps", "--force", "-f", "--frozen-lockfile"},
	},
	"yarn": {
		label:       "yarn",
		installSubs: []string{"add", "global"},
		valueFlags:  []string{"--registry", "--tag"},
		skipFlags:   []string{"-D", "--dev", "-P", "--peer", "-O", "--optional", "-E", "--exact", "-T", "--tilde", "--frozen-lockfile"},
	},
	"pnpm": {
		label:       "pnpm",
		installSubs: []string{"install", "i", "add"},
		valueFlags:  []string{"--workspace", "-w", "--registry"},
		skipFlags:   []string{"-D", "--save-dev", "-O", "--save-optional", "-g", "--global", "--save-exact", "-E", "--frozen-lockfile"},
	},
	"pip": {
		label:       "pip",
		installSubs: []string{"install"},
		valueFlags:  []string{"-r", "--requirement", "-t", "--target", "--prefix", "-i", "--index-url", "--extra-index-url", "-c", "--constraint", "--root"},
		skipFlags:   []string{"-U", "--upgrade", "--user", "--quiet", "-q", "--verbose", "-v", "--no-deps", "--pre"},
	},
	"pip3": {
		label:       "pip3",
		installSubs: []string{"install"},
		valueFlags:  []string{"-r", "--requirement", "-t", "--target", "--prefix", "-i", "--index-url", "--extra-index-url", "-c", "--constraint", "--root"},
		skipFlags:   []string{"-U", "--upgrade", "--user", "--quiet", "-q", "--verbose", "-v", "--no-deps", "--pre"},
	},
	"go": {
		label:       "go",
		installSubs: []string{"get", "install"},
		valueFlags:  []string{"-modfile", "-overlay", "-modcacherw"},
		skipFlags:   []string{"-u", "-d", "-v", "-t", "-fix", "-insecure"},
	},
	"cargo": {
		label:       "cargo",
		installSubs: []string{"add", "install"},
		valueFlags:  []string{"--version", "--git", "--branch", "--tag", "--rev", "--path", "--features", "--target", "--root"},
		skipFlags:   []string{"--no-default-features", "--all-features", "--locked", "--frozen", "--offline", "-q", "--quiet", "-v", "--verbose"},
	},
	"gem": {
		label:       "gem",
		installSubs: []string{"install"},
		valueFlags:  []string{"-v", "--version", "--platform", "-i", "--install-dir", "-n", "--bindir", "--source"},
		skipFlags:   []string{"--user-install", "--no-document", "--pre", "-P", "--trust-policy"},
	},
	"brew": {
		label:       "brew",
		installSubs: []string{"install", "reinstall"},
		valueFlags:  []string{},
		skipFlags:   []string{"--cask", "--formula", "--force", "--verbose", "-v", "--quiet", "-q", "--overwrite", "--dry-run", "-n"},
	},
	"apt": {
		label:       "apt",
		installSubs: []string{"install"},
		valueFlags:  []string{},
		skipFlags:   []string{"-y", "--yes", "--assume-yes", "-q", "--quiet", "--no-install-recommends", "--reinstall", "--fix-broken", "-f"},
	},
	"apt-get": {
		label:       "apt-get",
		installSubs: []string{"install"},
		valueFlags:  []string{},
		skipFlags:   []string{"-y", "--yes", "--assume-yes", "-q", "--quiet", "--no-install-recommends", "--reinstall", "--fix-broken", "-f"},
	},
	"composer": {
		label:       "composer",
		installSubs: []string{"require"},
		valueFlags:  []string{"--stability", "--prefer-source", "--prefer-dist"},
		skipFlags:   []string{"--dev", "--no-dev", "--no-update", "--dry-run", "-v", "--verbose"},
	},
	"bundle": {
		label:       "bundle",
		installSubs: []string{"add"},
		valueFlags:  []string{"--version", "--group", "--source", "--git", "--branch", "--ref", "--path"},
		skipFlags:   []string{"--skip-install", "--optimistic", "--strict"},
	},
	"nuget": {
		label:       "nuget",
		installSubs: []string{"install"},
		valueFlags:  []string{"-Version", "-Source", "-OutputDirectory", "-Framework"},
		skipFlags:   []string{"-NonInteractive", "-Prerelease", "-NoCache"},
	},
	"dotnet": {
		label:       "dotnet",
		installSubs: []string{"add"},
		valueFlags:  []string{"-v", "--version", "-f", "--framework", "-s", "--source"},
		skipFlags:   []string{"--prerelease", "--no-restore", "--interactive"},
	},
}

// detectPackageInstall checks whether args represent a package manager install
// invocation. If so, it returns the manager label and the list of package names.
func detectPackageInstall(base string, args []string) (isInstall bool, managerLabel string, packages []string) {
	def, ok := packageManagers[base]
	if !ok {
		return false, "", nil
	}
	if len(args) < 2 {
		return false, "", nil
	}

	sub := strings.ToLower(args[1])

	// Special case: `dotnet add package <name>`
	if base == "dotnet" && len(args) >= 3 && sub == "add" && strings.ToLower(args[2]) == "package" {
		pkgs := extractPackageNames(def, args[3:])
		return true, def.label, pkgs
	}

	matched := false
	for _, s := range def.installSubs {
		if sub == s {
			matched = true
			break
		}
	}
	if !matched {
		return false, "", nil
	}

	pkgs := extractPackageNames(def, args[2:])
	return true, def.label, pkgs
}

// extractPackageNames walks remaining args and returns tokens that look like
// package names, skipping flags and their associated values.
func extractPackageNames(def pkgManagerDef, remaining []string) []string {
	var pkgs []string
	skipNext := false
	for _, arg := range remaining {
		if skipNext {
			skipNext = false
			continue
		}
		// Pure boolean flag to skip
		if isBoolFlag(arg, def.skipFlags) {
			continue
		}
		// Value flag — skip this token and consume next as its value
		if isValueFlag(arg, def.valueFlags) {
			skipNext = true
			continue
		}
		// Attached flag prefix (e.g. --version=1.0)
		if hasAttachedPrefix(arg, def.attachedFlagPrefixes) {
			continue
		}
		// Any remaining flag-like token (starts with -)
		if strings.HasPrefix(arg, "-") {
			continue
		}
		pkgs = append(pkgs, arg)
	}
	return pkgs
}

func isBoolFlag(arg string, flags []string) bool {
	for _, f := range flags {
		if arg == f {
			return true
		}
	}
	return false
}

func isValueFlag(arg string, flags []string) bool {
	for _, f := range flags {
		if arg == f {
			return true
		}
	}
	return false
}

func hasAttachedPrefix(arg string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(arg, p+"=") {
			return true
		}
	}
	return false
}

// ── Command analysis ──────────────────────────────────────────────────────────

func analyzeCommand(args []string) CommandAnalysis {
	if len(args) == 0 {
		return CommandAnalysis{
			Command:     "(empty)",
			Risk:        RiskMedium,
			Warning:     "No command was provided to analyze.",
			PromptTip:   "Pass a shell command as an argument to Digest.",
			CommandBase: "",
		}
	}

	fullCommand := strings.Join(args, " ")
	base := strings.ToLower(filepathBase(args[0]))

	// ── 1. High-risk flag combinations ────────────────────────────────────────
	for cmd, flags := range highRiskFlags {
		if base == cmd {
			for _, flag := range flags {
				if strings.Contains(fullCommand, flag) {
					tip := fmt.Sprintf("This runs '%s' with a potentially destructive flag (%s). Double-check your intent before proceeding.", cmd, flag)
					return CommandAnalysis{
						Command:     fullCommand,
						RawArgs:     args,
						Risk:        RiskHigh,
						Warning:     fmt.Sprintf("'%s %s' can cause irreversible changes — this action may not be undoable.", cmd, flag),
						PromptTip:   tip,
						CommandBase: base,
					}
				}
			}
		}
	}

	// ── 2. High-risk base commands ────────────────────────────────────────────
	if tip, ok := highRiskPatterns[base]; ok {
		warning := fmt.Sprintf("'%s' is a high-risk command — proceed only if you are certain of the outcome.", base)
		if base == "sudo" && len(args) > 1 {
			warning = fmt.Sprintf("Running '%s' as root bypasses all normal user restrictions.", strings.Join(args[1:], " "))
		}
		return CommandAnalysis{
			Command:     fullCommand,
			RawArgs:     args,
			Risk:        RiskHigh,
			Warning:     warning,
			PromptTip:   tip,
			CommandBase: base,
		}
	}

	// ── 3. Package manager install detection ──────────────────────────────────
	// Run this before the low/medium fallback tables so that e.g. `go get` is
	// not silently treated as a generic low-risk `go` command.
	if isInstall, manager, pkgs := detectPackageInstall(base, args); isInstall {
		var pkgLine string
		if len(pkgs) == 0 {
			pkgLine = "(no specific packages — installing from lockfile or manifest)"
		} else if len(pkgs) == 1 {
			pkgLine = pkgs[0]
		} else {
			pkgLine = strings.Join(pkgs, ", ")
		}
		_ = pkgLine // used in View, not here
		return CommandAnalysis{
			Command:          fullCommand,
			RawArgs:          args,
			Risk:             RiskMedium,
			Warning:          fmt.Sprintf("'%s' will download and install software from the internet.", manager),
			PromptTip:        fmt.Sprintf("Package managers run installation scripts that can execute arbitrary code on your machine. Only install packages you trust."),
			CommandBase:      base,
			IsPackageInstall: true,
			Packages:         pkgs,
			PackageManager:   manager,
		}
	}

	// ── 4. Low-risk commands ──────────────────────────────────────────────────
	if tip, ok := lowRiskCommands[base]; ok {
		return CommandAnalysis{
			Command:     fullCommand,
			RawArgs:     args,
			Risk:        RiskLow,
			Warning:     fmt.Sprintf("'%s' is a read-only operation — no changes will be made to your system.", base),
			PromptTip:   tip,
			CommandBase: base,
		}
	}

	// ── 5. Medium-risk commands ───────────────────────────────────────────────
	if tip, ok := mediumRiskTips[base]; ok {
		return CommandAnalysis{
			Command:     fullCommand,
			RawArgs:     args,
			Risk:        RiskMedium,
			Warning:     fmt.Sprintf("'%s' will modify your system — review the arguments before approving.", base),
			PromptTip:   tip,
			CommandBase: base,
		}
	}

	// ── 6. Unknown command ────────────────────────────────────────────────────
	return CommandAnalysis{
		Command:     fullCommand,
		RawArgs:     args,
		Risk:        RiskMedium,
		Warning:     fmt.Sprintf("'%s' is an unrecognized command — review carefully before approving.", base),
		PromptTip:   fmt.Sprintf("Digest doesn't have details about '%s'. Verify its behavior with `man %s` or `--help` before running.", base, base),
		CommandBase: base,
	}
}

// filepathBase extracts the base name from a path.
func filepathBase(path string) string {
	parts := strings.Split(path, "/")
	return parts[len(parts)-1]
}

// ── Bubble Tea Model ──────────────────────────────────────────────────────────

type choice int

const (
	choiceApprove choice = iota
	choiceAbort
)

type model struct {
	analysis CommandAnalysis
	selected choice
	done     bool
	approved bool
}

type keyMap struct {
	Left  key.Binding
	Right key.Binding
	Tab   key.Binding
	Enter key.Binding
	Quit  key.Binding
}

var keys = keyMap{
	Left: key.NewBinding(
		key.WithKeys("left", "h"),
		key.WithHelp("←/h", "move left"),
	),
	Right: key.NewBinding(
		key.WithKeys("right", "l"),
		key.WithHelp("→/l", "move right"),
	),
	Tab: key.NewBinding(
		key.WithKeys("tab"),
		key.WithHelp("tab", "switch"),
	),
	Enter: key.NewBinding(
		key.WithKeys("enter"),
		key.WithHelp("enter", "confirm"),
	),
	Quit: key.NewBinding(
		key.WithKeys("ctrl+c", "q", "esc"),
		key.WithHelp("q/esc", "quit"),
	),
}

func initialModel(analysis CommandAnalysis) model {
	return model{
		analysis: analysis,
		selected: choiceApprove,
	}
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, keys.Quit):
			m.done = true
			m.approved = false
			return m, tea.Quit
		case key.Matches(msg, keys.Left):
			m.selected = choiceApprove
		case key.Matches(msg, keys.Right):
			m.selected = choiceAbort
		case key.Matches(msg, keys.Tab):
			if m.selected == choiceApprove {
				m.selected = choiceAbort
			} else {
				m.selected = choiceApprove
			}
		case key.Matches(msg, keys.Enter):
			m.done = true
			m.approved = m.selected == choiceApprove
			return m, tea.Quit
		}
	}
	return m, nil
}

// ── Styles ────────────────────────────────────────────────────────────────────

var (
	colorHighRisk   = lipgloss.Color("#FF4444")
	colorMediumRisk = lipgloss.Color("#FFB347")
	colorLowRisk    = lipgloss.Color("#44DD88")
	colorApprove    = lipgloss.Color("#22CC66")
	colorAbort      = lipgloss.Color("#FF4455")
	colorMuted      = lipgloss.Color("#888899")
	colorTitle      = lipgloss.Color("#E8E8F0")
	colorBg         = lipgloss.Color("#12121E")
	colorCardBorder = lipgloss.Color("#2A2A40")
	colorAccent     = lipgloss.Color("#7C6AFF")
	colorSubtle     = lipgloss.Color("#AAAACC")
	colorCaution    = lipgloss.Color("#FFB347")
	colorPkg        = lipgloss.Color("#5DD8FF")

	cardStyle = lipgloss.NewStyle().
			Background(colorBg).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorCardBorder).
			Padding(1, 3).
			Width(64)

	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorTitle).
			MarginBottom(1)

	commandStyle = lipgloss.NewStyle().
			Foreground(colorAccent).
			Bold(true).
			Background(lipgloss.Color("#1E1E30")).
			Padding(0, 1)

	sectionLabelStyle = lipgloss.NewStyle().
				Foreground(colorMuted).
				Bold(true).
				MarginTop(1)

	warningTextStyle = lipgloss.NewStyle().
				Foreground(colorSubtle)

	tipStyle = lipgloss.NewStyle().
			Foreground(colorSubtle).
			Italic(true)

	dividerStyle = lipgloss.NewStyle().
			Foreground(colorCardBorder)

	keymapStyle = lipgloss.NewStyle().
			Foreground(colorMuted).
			Italic(true)

	pkgNameStyle = lipgloss.NewStyle().
			Foreground(colorPkg).
			Bold(true)

	cautionStyle = lipgloss.NewStyle().
			Foreground(colorCaution).
			Bold(true)
)

func riskBadge(risk RiskLevel) string {
	var bg lipgloss.Color
	var label string
	switch risk {
	case RiskHigh:
		bg = colorHighRisk
		label = "  ● HIGH RISK  "
	case RiskMedium:
		bg = colorMediumRisk
		label = "  ◐ MEDIUM RISK  "
	case RiskLow:
		bg = colorLowRisk
		label = "  ○ LOW RISK  "
	}
	return lipgloss.NewStyle().
		Background(bg).
		Foreground(lipgloss.Color("#000000")).
		Bold(true).
		Padding(0, 1).
		Render(label)
}

func riskFg(risk RiskLevel) lipgloss.Color {
	switch risk {
	case RiskHigh:
		return colorHighRisk
	case RiskMedium:
		return colorMediumRisk
	default:
		return colorLowRisk
	}
}

func approveButton(selected bool) string {
	s := lipgloss.NewStyle().Padding(0, 4).Bold(true)
	if selected {
		return s.Background(colorApprove).Foreground(lipgloss.Color("#000000")).Render("✓  Approve")
	}
	return s.Foreground(colorApprove).Border(lipgloss.NormalBorder()).BorderForeground(colorApprove).Render("✓  Approve")
}

func abortButton(selected bool) string {
	s := lipgloss.NewStyle().Padding(0, 4).Bold(true)
	if selected {
		return s.Background(colorAbort).Foreground(lipgloss.Color("#000000")).Render("✗  Abort")
	}
	return s.Foreground(colorAbort).Border(lipgloss.NormalBorder()).BorderForeground(colorAbort).Render("✗  Abort")
}

func divider(width int) string {
	return dividerStyle.Render(strings.Repeat("─", width))
}

// ── View ──────────────────────────────────────────────────────────────────────

func (m model) View() string {
	a := m.analysis
	div := divider(58)

	// Header
	header := lipgloss.JoinHorizontal(
		lipgloss.Left,
		titleStyle.Render("digest"),
		"  ",
		riskBadge(a.Risk),
	)

	// Command block
	cmdBlock := lipgloss.JoinVertical(
		lipgloss.Left,
		sectionLabelStyle.Render("COMMAND"),
		commandStyle.Render("$ "+a.Command),
	)

	// Package block (only for package manager installs)
	var pkgBlock string
	if a.IsPackageInstall {
		var pkgLines []string
		if len(a.Packages) == 0 {
			pkgLines = append(pkgLines,
				lipgloss.NewStyle().Foreground(colorMuted).Italic(true).Render(
					"  (no specific packages — installing from lockfile or manifest)",
				),
			)
		} else {
			for _, p := range a.Packages {
				pkgLines = append(pkgLines,
					"  "+pkgNameStyle.Render("▸ "+p),
				)
			}
		}
		cautionLine := cautionStyle.Render("⚡ Caution: ") +
			warningTextStyle.Render("This will execute external code during the installation process.")

		pkgBlock = lipgloss.JoinVertical(
			lipgloss.Left,
			append(
				[]string{sectionLabelStyle.Render("PACKAGES  (" + a.PackageManager + ")")},
				append(pkgLines, "", cautionLine)...,
			)...,
		)
	}

	// Risk assessment
	riskBlock := lipgloss.JoinVertical(
		lipgloss.Left,
		sectionLabelStyle.Render("RISK ASSESSMENT"),
		lipgloss.NewStyle().Foreground(riskFg(a.Risk)).Render("⚠  ")+warningTextStyle.Render(a.Warning),
	)

	// Prompt tip
	tipBlock := lipgloss.JoinVertical(
		lipgloss.Left,
		sectionLabelStyle.Render("PROMPT TIP"),
		lipgloss.NewStyle().Foreground(colorAccent).Render("ℹ  ")+tipStyle.Render(a.PromptTip),
	)

	// Buttons
	buttonSection := lipgloss.JoinVertical(
		lipgloss.Left,
		sectionLabelStyle.Render("ACTION"),
		lipgloss.JoinHorizontal(
			lipgloss.Left,
			approveButton(m.selected == choiceApprove),
			"    ",
			abortButton(m.selected == choiceAbort),
		),
	)

	// Key hints
	hint := keymapStyle.Render("← → tab  navigate    enter  confirm    q / esc  quit")

	// Assemble body — insert pkgBlock between command and risk sections
	sections := []string{header, div, cmdBlock}
	if a.IsPackageInstall {
		sections = append(sections, div, pkgBlock)
	}
	sections = append(sections, div, riskBlock, tipBlock, div, buttonSection, "", hint)

	body := lipgloss.JoinVertical(lipgloss.Left, sections...)
	return "\n" + cardStyle.Render(body) + "\n"
}

// ── Entry Point ───────────────────────────────────────────────────────────────

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: digest <command> [args...]")
		fmt.Fprintln(os.Stderr, "Example: digest npm install express")
		os.Exit(1)
	}

	analysis := analyzeCommand(args)
	m := initialModel(analysis)

	p := tea.NewProgram(m, tea.WithOutput(os.Stderr))
	result, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	finalModel, ok := result.(model)
	if !ok {
		os.Exit(1)
	}

	if !finalModel.approved {
		fmt.Fprintln(os.Stderr, "\nAborted.")
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "\nExecuting...")

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "Error executing command: %v\n", err)
		os.Exit(1)
	}
}
