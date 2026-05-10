# Command-Guard (digest)

**The pedagogical guardrail for agentic workflows.**

---

## The Problem: The Silent Actor

Modern AI coding agents are remarkably capable — and remarkably opaque. When an agent decides to run `rm -rf ./dist`, `git push --force`, or `npm install` a dependency it found on the internet, it does so silently. There is no checkpoint. No explanation. No moment for a human to say *wait*.

This is the **Silent Actor** problem: an agent that acts on your behalf, against your filesystem and network, with zero transparency about what it is doing or why. The risk compounds at the edges — not in the obvious commands every developer knows, but in the compounding chain of incidental tool calls that accumulate across a session.

Command-Guard (`digest`) is a deliberate intervention at that boundary.

---

## What Digest Does

Digest is a TUI-based review layer that wraps any shell command. Before execution, it intercepts the call, classifies it by threat level, surfaces an educational explanation of what the command does and why it may be risky, and requires explicit human approval. If you approve, the command runs with full interactivity — stdin, stdout, and stderr forwarded directly. If you abort, the process exits with code `1`.

It is not a firewall. It is not a sandbox. It is a **pedagogical guardrail** — a tool that makes the implicit explicit and gives a human (or a supervised agent) a moment of genuine informed consent before anything happens to their system.

---

## Features

### Risk-Weighted Assessments

Every command is scored against a three-tier threat model:

| Level | Colour | Meaning |
|-------|--------|---------|
| `HIGH` | Red | Destructive, privileged, or irreversible. Requires deliberate approval. |
| `MEDIUM` | Amber | Modifies system state. Review arguments before proceeding. |
| `LOW` | Green | Read-only. No lasting changes to the system. |

The classifier reasons over:

- **Base command** — `rm`, `sudo`, `dd`, `shred`, `chmod`, `kill`, and a full registry of known dangerous tools are immediately escalated to `HIGH`.
- **Flag combinations** — `git push --force`, `git reset --hard`, `git clean -f`, `curl -X DELETE`, and other destructive flag patterns are caught even when the base command is otherwise benign.
- **Dangerous substrings** — raw device redirections (`> /dev/sda`, `> /dev/nvme`), output suppression (`>/dev/null`, `2>/dev/null`, `&>/dev/null`), force flags (`--force`, `-f`), and pipe-to-`dd` patterns are scanned case-insensitively across the full command string.
- **Package manager installs** — any install invocation is classified `MEDIUM` and triggers the dedicated package analysis path described below.

### Lip Gloss Styled TUI Cards

Digest renders a structured card interface using [Lip Gloss](https://github.com/charmbracelet/lipgloss) and [Bubble Tea](https://github.com/charmbracelet/bubbletea). The card width adapts dynamically to the terminal width (clamped 36–80 columns):

```
┃ digest   ● HIGH                                               ┃
┃ ──────────────────────────────────────────────────────────── ┃
┃ COMMAND                                                       ┃
┃   $ rm -rf ./dist                                             ┃
┃ ──────────────────────────────────────────────────────────── ┃
┃ THREAT LEVEL                                                  ┃
┃ ▲  'rm' is a high-risk command — proceed only if you are      ┃
┃    certain of the outcome.                                    ┃
┃                                                               ┃
┃ PROMPT TIP                                                    ┃
┃ ℹ  Permanently removes files or directories — cannot be       ┃
┃    undone.                                                    ┃
┃ ──────────────────────────────────────────────────────────── ┃
┃ ACTION                                                        ┃
┃  ✓  Approve     ┌────────────────┐                           ┃
┃                 │  ✗  Abort      │                           ┃
┃                 └────────────────┘                           ┃
```

For package manager commands, a dedicated **PACKAGES** section is injected:

```
┃ PACKAGES  (npm)                                               ┃
┃   ▸ express                                                   ┃
┃   ▸ lodash                                                    ┃
┃                                                               ┃
┃ ⚡ Caution: This will execute external code during the        ┃
┃             installation process.                             ┃
```

### Package Manager Intelligence

Digest understands 15 package managers out of the box:

`npm` · `yarn` · `pnpm` · `pip` · `pip3` · `go` · `cargo` · `gem` · `brew` · `apt` · `apt-get` · `composer` · `bundle` · `nuget` · `dotnet`

### Zero-Latency Execution

When approved, Digest calls `os/exec` with `cmd.Stdin`, `cmd.Stdout`, and `cmd.Stderr` bound directly to the parent process. Interactive programs — REPLs, editors, progress bars, pagers — work exactly as they would if invoked directly. Exit codes are propagated faithfully.

---

## Project Layout

```
Command-Guard/
├── cmd/
│   └── digest/
│       └── main.go          # Entry point — wires analyzer → ui → exec
├── internal/
│   ├── analyzer/
│   │   ├── analyzer.go      # Risk classification and package detection
│   │   └── analyzer_test.go # Full test suite (31 cases, race-safe)
│   ├── ui/
│   │   ├── ui.go            # Bubble Tea model and Lip Gloss card renderer
│   │   └── stderr.go        # Stderr accessor
│   └── exec/
│       └── exec.go          # Streaming command execution, exit-code propagation
├── scripts/
│   └── smoke_test.sh        # End-to-end smoke test (10 assertions)
├── Makefile
├── LICENSE
└── README.md
```

---

## Installation

### Using `go install`

```bash
go install github.com/youwantitdarker28/Command-Guard/cmd/digest@latest
```

### Build from source

```bash
git clone https://github.com/youwantitdarker28/Command-Guard
cd Command-Guard
make build          # produces ./digest
make install        # installs to /usr/local/bin/digest
```

Override the install prefix:

```bash
make install PREFIX=~/.local
```

---

## Usage

```
digest <command> [args...]
```

### Examples

```bash
# High risk — destructive delete
digest rm -rf ./dist

# High risk — force push rewrites remote history
digest git push --force

# High risk — root privilege escalation
digest sudo systemctl restart nginx

# High risk — raw device write
digest dd if=/dev/urandom of=/dev/sda bs=4M

# Medium risk — package install (package names are extracted and listed)
digest npm install express lodash
digest go get github.com/charmbracelet/bubbletea@latest
digest pip install requests flask --upgrade
digest cargo add serde --features derive

# Low risk — read-only, no approval anxiety
digest ls -la
digest git log --oneline -20
digest grep -r "TODO" ./src
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Command approved and completed successfully |
| `1` | User aborted, or command exited with an error |
| `N` | The executed command's own exit code, propagated faithfully |

### Key bindings

| Key | Action |
|-----|--------|
| `←` / `h` | Select **Approve** |
| `→` / `l` | Select **Abort** |
| `Tab` | Toggle selection |
| `Enter` | Confirm current selection |
| `q` / `Esc` / `Ctrl+C` | Quit (equivalent to Abort) |

---

## Integration with AI Agents

Drop Digest in front of any shell command an agent would otherwise execute silently:

```python
# Before
subprocess.run(["rm", "-rf", "./dist"])

# After — a human reviews before anything runs
subprocess.run(["digest", "rm", "-rf", "./dist"])
```

Or alias it at the shell level in the agent's execution environment:

```bash
alias rm='digest rm'
alias git='digest git'
alias npm='digest npm'
```

The card renders to stderr; the command's own output goes to stdout. Structured output pipelines are not disrupted.

---

## Development

```bash
make test        # run full test suite with race detection
make vet         # run go vet
make tidy        # sync go.mod / go.sum
make smoke-test  # build + run end-to-end smoke tests
make clean       # remove compiled binary
```

### CI escape hatch

```bash
DIGEST_AUTO_APPROVE=1 digest echo success
```

Setting `DIGEST_AUTO_APPROVE=1` bypasses the interactive TUI entirely, making Digest scriptable in pipelines and smoke tests.

---

## License

MIT — see [LICENSE](LICENSE).

## Governance policies

Digest supports a local governance policy layer using YAML files.

Policy lookup order:
1. `./digest.policy.yaml`
2. `~/.digest/policy.yaml`

The first file found is loaded. If no policy file exists, Digest keeps the existing default behavior (approval UI for commands).

Example:

```yaml
version: 1
mode: personal

rules:
  - match: "git push --force"
    action: block

  - match: "rm -rf"
    action: require_approval
    reason_required: true

  - category: package_install
    action: require_approval

  - category: read_only
    action: allow

audit:
  enabled: true
  path: ~/.digest/audit.log
```

### Actions

- `allow`: execute immediately (skip TUI)
- `warn`: show approval UI
- `require_approval`: show approval UI
- `block`: deny execution and exit non-zero

Rules are evaluated top-to-bottom and the first matching rule wins.

Rule matching supports:
- `match`: substring match against the full command string
- `category`: match against digest command categories (`read_only`, `package_install`, `destructive`, `privilege_escalation`, `git_history_rewrite`, `network`, `unknown`)

### Audit log

When `audit.enabled: true`, Digest appends JSONL records to the configured path.

Each entry includes:
- `timestamp`
- `command`
- `risk`
- `category`
- `policy_action`
- `decision`

Audit writes are best-effort: if logging fails, Digest prints a warning to stderr and continues command flow.
