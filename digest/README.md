# Digest

**The pedagogical guardrail for agentic workflows.**

---

## The Problem: The Silent Actor

Modern AI coding agents are remarkably capable — and remarkably opaque. When an agent decides to run `rm -rf ./dist`, `git push --force`, or `npm install` a dependency it found on the internet, it does so silently. There is no checkpoint. No explanation. No moment for a human to say *wait*.

This is the **Silent Actor** problem: an agent that acts on your behalf, against your filesystem and network, with zero transparency about what it is doing or why. The risk compounds at the edges — not in the obvious commands every developer knows, but in the compounding chain of incidental tool calls that accumulate across a session.

Digest is a deliberate intervention at that boundary.

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
- **Dangerous substrings** — raw device redirections (`> /dev/sda`, `> /dev/nvme`), force flags (`--force`, `-f`), and pipe-to-`dd` patterns are scanned across the full command string.
- **Package manager installs** — any install invocation is classified `MEDIUM` and triggers the dedicated package analysis path described below.

### Lip Gloss Styled TUI Cards

Digest renders a structured card interface using [Lip Gloss](https://github.com/charmbracelet/lipgloss) and [Bubble Tea](https://github.com/charmbracelet/bubbletea):

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

For package manager commands, a dedicated **PACKAGES** section is injected between the command block and the threat assessment, listing every package name extracted from the command arguments — with a prominent caution notice:

```
┃ PACKAGES  (npm)                                               ┃
┃   ▸ express                                                   ┃
┃   ▸ lodash                                                    ┃
┃                                                               ┃
┃ ⚡ Caution: This will execute external code during the        ┃
┃             installation process.                             ┃
```

Flag stripping is applied across all supported package managers so that only genuine package names appear — not `--save-dev`, `--upgrade`, `-r requirements.txt`, or similar noise.

### Package Manager Intelligence

Digest understands 13 package managers out of the box:

`npm` · `yarn` · `pnpm` · `pip` · `pip3` · `go` · `cargo` · `gem` · `brew` · `apt` · `apt-get` · `composer` · `bundle` · `nuget` · `dotnet`

It distinguishes between install subcommands (`npm install`, `go get`, `cargo add`) and non-install subcommands (`npm run`, `go build`, `cargo test`), and handles edge cases like `dotnet add package`, lockfile-only installs with no explicit package names, and version-pinned module paths (`github.com/foo/bar@v1.2.3`).

### Zero-Latency Execution

When approved, Digest calls `os/exec` with `cmd.Stdin`, `cmd.Stdout`, and `cmd.Stderr` bound directly to the parent process. There is no buffering, no capture, and no transformation of the output stream. Interactive programs — REPLs, editors, progress bars, pagers — work exactly as they would if invoked directly. Exit codes are propagated faithfully.

---

## Project Layout

This project follows the [Standard Go Project Layout](https://github.com/golang-standards/project-layout):

```
digest/
├── cmd/
│   └── digest/
│       └── main.go          # Entry point — wires analyzer → ui → exec
├── internal/
│   ├── analyzer/
│   │   ├── analyzer.go      # Risk classification and package detection
│   │   └── analyzer_test.go # Full test suite for the classifier
│   ├── ui/
│   │   └── ui.go            # Bubble Tea model and Lip Gloss card renderer
│   └── exec/
│       └── exec.go          # Streaming command execution
├── Makefile
├── LICENSE
└── README.md
```

---

## Installation

### Using `go install`

```bash
go install github.com/digest/cmd/digest@latest
```

### Build from source

```bash
git clone https://github.com/your-org/digest
cd digest
make build          # produces ./digest
make install        # installs to /usr/local/bin/digest
```

You can override the install prefix:

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

Digest is designed to be dropped in front of any shell command an agent would otherwise execute silently. Wrap your agent's shell execution tool:

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
make test    # run full test suite with race detection
make vet     # run go vet
make tidy    # sync go.mod / go.sum
make clean   # remove compiled binary
```

---

## License

MIT — see [LICENSE](LICENSE).
