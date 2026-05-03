// Package analyzer classifies shell commands by risk level and detects
// package-manager install invocations, extracting the packages being installed.
package analyzer

import (
	"fmt"
	"strings"
)

// ── Risk level ────────────────────────────────────────────────────────────────

// RiskLevel represents the assessed danger of a command.
type RiskLevel int

const (
	RiskLow    RiskLevel = iota // read-only; no side effects
	RiskMedium                  // modifies state; review recommended
	RiskHigh                    // destructive or privileged; explicit approval required
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

// ── Result ────────────────────────────────────────────────────────────────────

// Result is the complete analysis of a shell command.
type Result struct {
	Command          string    // full command string as entered
	RawArgs          []string  // original argument slice
	CommandBase      string    // lowercase base name of args[0]
	Risk             RiskLevel // assessed threat level
	ThreatSummary    string    // one-sentence risk statement shown under THREAT LEVEL
	PromptTip        string    // educational one-liner about what the command does
	IsPackageInstall bool      // true when a dependency manager install was detected
	PackageManager   string    // display name of the package manager (e.g. "npm")
	Packages         []string  // package names being installed; empty = lockfile install
}

// ── High-risk base commands ───────────────────────────────────────────────────

var highRiskCommands = map[string]string{
	"rm":       "Permanently removes files or directories — cannot be undone.",
	"sudo":     "Runs commands with root (superuser) privileges — full system access.",
	"chmod":    "Changes file permissions — incorrect use can lock you out of files.",
	"chown":    "Changes file ownership — can revoke your own access to files.",
	"dd":       "Writes raw data byte-for-byte to any device — one typo can wipe a drive.",
	"mkfs":     "Formats a filesystem, erasing all data on the target device.",
	"fdisk":    "Manages low-level disk partitions — destructive changes are immediate.",
	"shred":    "Overwrites files to make recovery impossible — fully irreversible.",
	"truncate": "Shrinks or empties a file — data beyond the new size is lost.",
	"kill":     "Sends a signal to a process — can terminate critical services.",
	"killall":  "Kills every process matching a name — wide and indiscriminate.",
	"pkill":    "Kills processes by pattern — easy to hit unintended targets.",
	"wipefs":   "Erases filesystem signatures from a device, preparing it for reformat.",
	"parted":   "Interactively manages partitions — mistakes are not automatically undone.",
}

// highRiskFlagPatterns maps a base command to substrings in the full command
// that elevate it to HIGH risk. Matching is case-insensitive (both sides are
// lowercased before comparison in Analyze).
var highRiskFlagPatterns = map[string][]string{
	"git":  {"push -f", "push --force", "push --force-with-lease", "reset --hard", "clean -f", "clean --force"},
	"npm":  {"publish"},
	"yarn": {"publish"},
	"curl": {"-x delete", "--request delete", "-x put", "--request put"},
	"wget": {"--delete-after"},
}

// dangerousPatterns are scanned case-insensitively against the full command
// string. They catch shell constructs (redirections, device paths, force flags,
// output suppression) that no per-command classifier can reliably detect.
//
// Each entry carries:
//   - pattern: the substring to search for (must be lowercase; the scan
//     lowercases the command before comparison, giving case-insensitive matching)
//   - tip:     the human-readable explanation shown in the PROMPT TIP section
var dangerousPatterns = []struct {
	pattern string
	tip     string
}{
	// ── Output suppression — can conceal agent activity ──────────────────────
	// Ordered longest-first so the most specific match wins.
	{
		"&>/dev/null",
		"Redirecting both stdout and stderr to /dev/null silences the command completely — errors and output are invisible, making it impossible to verify what ran.",
	},
	{
		">/dev/null",
		"Redirecting stdout to /dev/null discards all output — any errors or confirmations will be hidden from the operator.",
	},
	{
		"2>/dev/null",
		"Redirecting stderr to /dev/null silences error messages — failures will occur without any visible indication.",
	},
	{
		"> /dev/null",
		"Redirecting output to /dev/null discards all command output — results and errors will not be visible.",
	},
	{
		"2> /dev/null",
		"Redirecting error output to /dev/null silences all error messages — failures will occur silently.",
	},

	// ── Raw device writes ────────────────────────────────────────────────────
	{"> /dev/sd", "Redirecting output to a block device (/dev/sd*) overwrites raw disk sectors — data loss is immediate and permanent."},
	{"> /dev/hd", "Redirecting output to a hard disk device node will destroy data on that drive."},
	{"> /dev/nvme", "Redirecting output to an NVMe device will overwrite the device's raw sectors."},
	{"> /dev/disk", "Redirecting output to a disk device node is a destructive low-level write operation."},
	{"> /dev/vd", "Redirecting to a virtual disk device will overwrite its contents."},

	// ── Pipe-to-dd ───────────────────────────────────────────────────────────
	{"| dd ", "Piping output through dd writes raw bytes to the destination — verify the target before proceeding."},

	// ── Force flags (case-insensitive via lowercased scan) ───────────────────
	{"--force", "The --force flag suppresses safety checks and confirmation prompts — the command will not ask for verification."},
	{" -f ", "The -f (force) flag disables interactive confirmation on many commands — changes will be applied without further prompts."},
	{"-f\t", "The -f (force) flag disables interactive confirmation on many commands."},
}

// ── Low-risk commands (read-only) ─────────────────────────────────────────────

var lowRiskCommands = map[string]string{
	"ls":       "Lists files and directories in the specified path.",
	"cat":      "Reads and prints the contents of a file to stdout.",
	"echo":     "Prints text to the terminal output.",
	"pwd":      "Prints the absolute path of the current working directory.",
	"whoami":   "Displays the username of the current session.",
	"date":     "Displays the current date and time.",
	"cal":      "Renders a calendar for the current month.",
	"which":    "Resolves the filesystem path of an executable command.",
	"type":     "Describes how the shell will interpret a given token.",
	"file":     "Identifies the type and encoding of a file.",
	"wc":       "Counts lines, words, and bytes in a file or stdin.",
	"head":     "Prints the first N lines of a file.",
	"tail":     "Prints the last N lines of a file (or follows new output with -f).",
	"grep":     "Searches for a regular expression pattern within files or stdin.",
	"find":     "Walks the filesystem tree searching for files matching criteria.",
	"sort":     "Sorts lines of text from a file or stdin.",
	"uniq":     "Filters adjacent duplicate lines from input.",
	"diff":     "Compares two files line-by-line and reports differences.",
	"man":      "Opens the system manual page for a command.",
	"help":     "Prints usage information for a shell built-in.",
	"env":      "Lists all exported environment variables.",
	"printenv": "Prints the value of one or more environment variables.",
	"uname":    "Reports the operating system name and kernel version.",
	"uptime":   "Reports how long the system has been running.",
	"df":       "Shows available and used disk space across mounted filesystems.",
	"du":       "Reports disk usage of files and directories.",
	"ps":       "Snapshots the currently running processes.",
	"top":      "Provides a live, updating view of system resource usage.",
	"htop":     "An enhanced, interactive process viewer.",
	"ping":     "Sends ICMP echo requests to test network reachability.",
	"curl":     "Transfers data from or to a network endpoint.",
	"wget":     "Downloads files from the internet to the local filesystem.",
	"git":      "Distributed version control — tracks changes across your codebase.",
	"go":       "Compiles, tests, and runs Go programs.",
	"node":     "Executes JavaScript with the Node.js runtime.",
	"python":   "Runs a Python script or starts the interactive interpreter.",
	"python3":  "Runs a Python 3 script or starts the interactive interpreter.",
}

// ── Medium-risk commands ──────────────────────────────────────────────────────

var mediumRiskCommands = map[string]string{
	"mv":      "Moves or renames files — the source path will no longer exist.",
	"cp":      "Copies files or directories to a new location.",
	"mkdir":   "Creates a new directory at the specified path.",
	"touch":   "Creates an empty file or updates a file's access/modification timestamps.",
	"tar":     "Creates or extracts archive files — review flags carefully.",
	"zip":     "Compresses files into a ZIP archive.",
	"unzip":   "Extracts files from a ZIP archive.",
	"apt":     "Manages packages on Debian/Ubuntu — requires elevated privileges.",
	"apt-get": "Low-level interface to the APT package system.",
	"brew":    "macOS package manager — installs software from formulae.",
	"pip":     "Installs Python packages from PyPI — executes code from the registry.",
	"pip3":    "Installs Python 3 packages from PyPI.",
	"npm":     "JavaScript package manager — can run pre/post-install scripts.",
	"yarn":    "JavaScript package manager with deterministic installs.",
	"pnpm":    "Fast, disk-efficient JavaScript package manager.",
	"docker":  "Builds and runs containerized applications.",
	"ssh":     "Opens an encrypted shell session on a remote machine.",
	"scp":     "Copies files securely between local and remote hosts.",
	"rsync":   "Synchronises files between locations — can silently overwrite the destination.",
	"make":    "Executes build targets defined in a Makefile — arbitrary shell code.",
	"cron":    "Manages the system task scheduler.",
	"crontab": "Edits the per-user cron job table.",
	"export":  "Sets an environment variable for the duration of the session.",
	"source":  "Executes a script in the current shell environment.",
	"bash":    "Starts a new Bash shell or executes a shell script.",
	"sh":      "Starts a POSIX sh shell or executes a shell script.",
	"zsh":     "Starts a Zsh shell or executes a Zsh script.",
}

// ── Package manager detection ─────────────────────────────────────────────────

// pkgManagerDef describes a package manager's install subcommand vocabulary
// and the flags that should be stripped when extracting package names.
type pkgManagerDef struct {
	label       string   // human-readable name shown in the UI
	installSubs []string // subcommands that mean "install packages"
	valueFlags  []string // flags that consume the next token as their value
	skipFlags   []string // boolean flags to skip (no value consumed)
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
		valueFlags:  []string{"-modfile", "-overlay"},
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
		skipFlags:   []string{"--user-install", "--no-document", "--pre"},
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
		valueFlags:  []string{"--stability"},
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

// detectPackageInstall returns whether args is a package-manager install
// invocation, along with the manager label and extracted package names.
func detectPackageInstall(base string, args []string) (isInstall bool, managerLabel string, packages []string) {
	def, ok := packageManagers[base]
	if !ok || len(args) < 2 {
		return false, "", nil
	}

	sub := strings.ToLower(args[1])

	// Special case: `dotnet add package <name>`
	if base == "dotnet" && len(args) >= 3 && sub == "add" && strings.ToLower(args[2]) == "package" {
		return true, def.label, extractPackageNames(def, args[3:])
	}

	for _, s := range def.installSubs {
		if sub == s {
			return true, def.label, extractPackageNames(def, args[2:])
		}
	}
	return false, "", nil
}

// extractPackageNames strips flags and their values from remaining args,
// returning only the tokens that represent package names.
func extractPackageNames(def pkgManagerDef, remaining []string) []string {
	var pkgs []string
	skipNext := false
	for _, arg := range remaining {
		if skipNext {
			skipNext = false
			continue
		}
		if isFlagIn(arg, def.skipFlags) {
			continue
		}
		if isFlagIn(arg, def.valueFlags) {
			skipNext = true
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		pkgs = append(pkgs, arg)
	}
	return pkgs
}

func isFlagIn(arg string, flags []string) bool {
	for _, f := range flags {
		if arg == f {
			return true
		}
	}
	return false
}

// ── Public API ────────────────────────────────────────────────────────────────

// Analyze classifies a shell command and returns a complete Result.
func Analyze(args []string) Result {
	if len(args) == 0 {
		return Result{
			Command:       "(empty)",
			Risk:          RiskMedium,
			ThreatSummary: "No command was provided to analyze.",
			PromptTip:     "Pass a shell command as an argument to Digest.",
		}
	}

	fullCommand := strings.Join(args, " ")
	base := strings.ToLower(baseName(args[0]))

	// lowerCmd is used exclusively for case-insensitive pattern scanning.
	// The original fullCommand is preserved for display.
	lowerCmd := strings.ToLower(fullCommand)

	// ── 1. Case-insensitive dangerous-pattern scan ────────────────────────────
	// Patterns are already lowercase; lowercasing lowerCmd makes matching
	// case-insensitive for free (handles --FORCE, &>/DEV/NULL, etc.).
	for _, pat := range dangerousPatterns {
		if strings.Contains(lowerCmd, pat.pattern) {
			return Result{
				Command:       fullCommand,
				RawArgs:       args,
				CommandBase:   base,
				Risk:          RiskHigh,
				ThreatSummary: fmt.Sprintf("Command contains a dangerous construct (%q) — review carefully.", pat.pattern),
				PromptTip:     pat.tip,
			}
		}
	}

	// ── 2. High-risk flag combinations (case-insensitive) ────────────────────
	if patterns, ok := highRiskFlagPatterns[base]; ok {
		for _, pat := range patterns {
			// pat values in highRiskFlagPatterns are already lowercase;
			// comparing against lowerCmd makes the check case-insensitive.
			if strings.Contains(lowerCmd, pat) {
				return Result{
					Command:       fullCommand,
					RawArgs:       args,
					CommandBase:   base,
					Risk:          RiskHigh,
					ThreatSummary: fmt.Sprintf("'%s %s' can cause irreversible changes — this action may not be undoable.", base, pat),
					PromptTip:     fmt.Sprintf("The '%s' flag suppresses safety guards. Double-check your intent before proceeding.", pat),
				}
			}
		}
	}

	// ── 3. High-risk base commands ────────────────────────────────────────────
	if tip, ok := highRiskCommands[base]; ok {
		summary := fmt.Sprintf("'%s' is a high-risk command — proceed only if you are certain of the outcome.", base)
		if base == "sudo" && len(args) > 1 {
			summary = fmt.Sprintf("Running '%s' as root bypasses all normal user restrictions.", strings.Join(args[1:], " "))
		}
		return Result{
			Command:       fullCommand,
			RawArgs:       args,
			CommandBase:   base,
			Risk:          RiskHigh,
			ThreatSummary: summary,
			PromptTip:     tip,
		}
	}

	// ── 4. Package manager install detection ──────────────────────────────────
	if isInstall, manager, pkgs := detectPackageInstall(base, args); isInstall {
		return Result{
			Command:          fullCommand,
			RawArgs:          args,
			CommandBase:      base,
			Risk:             RiskMedium,
			ThreatSummary:    fmt.Sprintf("'%s' will download and execute code from the internet.", manager),
			PromptTip:        "Package managers can run pre/post-install scripts that execute arbitrary code on your machine. Only install packages from sources you trust.",
			IsPackageInstall: true,
			PackageManager:   manager,
			Packages:         pkgs,
		}
	}

	// ── 5. Low-risk commands ──────────────────────────────────────────────────
	if tip, ok := lowRiskCommands[base]; ok {
		return Result{
			Command:       fullCommand,
			RawArgs:       args,
			CommandBase:   base,
			Risk:          RiskLow,
			ThreatSummary: fmt.Sprintf("'%s' is a read-only operation — no lasting changes will be made to your system.", base),
			PromptTip:     tip,
		}
	}

	// ── 6. Medium-risk commands ───────────────────────────────────────────────
	if tip, ok := mediumRiskCommands[base]; ok {
		return Result{
			Command:       fullCommand,
			RawArgs:       args,
			CommandBase:   base,
			Risk:          RiskMedium,
			ThreatSummary: fmt.Sprintf("'%s' will modify system state — review the arguments before approving.", base),
			PromptTip:     tip,
		}
	}

	// ── 7. Unknown command ────────────────────────────────────────────────────
	return Result{
		Command:       fullCommand,
		RawArgs:       args,
		CommandBase:   base,
		Risk:          RiskMedium,
		ThreatSummary: fmt.Sprintf("'%s' is unrecognized — review carefully before approving.", base),
		PromptTip:     fmt.Sprintf("Digest has no profile for '%s'. Check `man %s` or `%s --help` before running.", base, base, base),
	}
}

// baseName returns the last path component of a string.
func baseName(path string) string {
	parts := strings.Split(path, "/")
	return parts[len(parts)-1]
}
