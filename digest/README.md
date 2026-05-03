# Digest

A production-ready CLI wrapper built with [Bubble Tea](https://github.com/charmbracelet/bubbletea) and [Lip Gloss](https://github.com/charmbracelet/lipgloss).

Digest intercepts any shell command, classifies its risk, gives you an educational tip, then asks you to **Approve** or **Abort** before anything runs.

```
digest rm -rf ./tmp
```

## Features

- **Risk Classification** — automatically categorises commands as High / Medium / Low risk
  - **High**: `rm`, `sudo`, `chmod`, `dd`, `git push --force`, and more
  - **Low**: read-only commands like `ls`, `cat`, `grep`, `git log`, etc.
  - **Medium**: everything else
- **Rich TUI Card** — styled layout with Lip Gloss: command display, risk badge, warning, and tip
- **Educational Coaching** — a one-line explanation of what the command does
- **Interactive Approve / Abort** — keyboard-navigable buttons; press Enter to confirm
- **Streaming Execution** — approved commands run with full interactivity (stdin, stdout, stderr all wired)
- **Exit Code Propagation** — aborted commands exit with code 1; executed commands relay the real exit code

## Installation

**Build locally:**

```bash
cd digest
make build
# binary: ./digest/digest
```

**Install to PATH:**

```bash
cd digest
make install
# binary placed in $(go env GOPATH)/bin/digest
```

## Usage

```bash
digest <command> [args...]
```

### Examples

```bash
digest rm -rf ./tmp          # HIGH risk — confirms before deleting
digest sudo apt update       # HIGH risk — root privileges warning
digest git push --force      # HIGH risk — destructive push warning
digest ls -la                # LOW risk  — read-only, safe
digest mv old.txt new.txt    # MEDIUM risk — file modification
```

## Controls

| Key | Action |
|-----|--------|
| `←` / `h` | Select Approve |
| `→` / `l` | Select Abort |
| `Tab` | Toggle selection |
| `Enter` | Confirm selection |
| `q` / `Esc` / `Ctrl+C` | Quit (same as Abort) |

## Requirements

- Go 1.21+

## Dependencies

- [Bubble Tea](https://github.com/charmbracelet/bubbletea) — TUI framework
- [Lip Gloss](https://github.com/charmbracelet/lipgloss) — terminal styling
- [Bubbles](https://github.com/charmbracelet/bubbles) — key binding helpers
