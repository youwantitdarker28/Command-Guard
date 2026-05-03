# Command-Guard

A production-ready Go CLI tool (`digest`) — a TUI-based review layer for shell commands using Bubble Tea + Lip Gloss.

## Module

```
github.com/youwantitdarker28/Command-Guard
```

## Repository Layout

```
/                              ← Go project root (go.mod lives here)
├── cmd/digest/main.go         ← Entry point: parse → analyze → TUI → exec → exit code
├── internal/
│   ├── analyzer/
│   │   ├── analyzer.go        ← Risk classification + dangerous pattern scan + package detection
│   │   └── analyzer_test.go   ← 31-case parallel test suite (race-safe)
│   ├── ui/
│   │   ├── ui.go              ← Bubble Tea model, WindowSizeMsg, dynamic card width, DIGEST_AUTO_APPROVE
│   │   └── stderr.go          ← Stderr accessor
│   └── exec/
│       └── exec.go            ← Streaming os/exec wrapper, returns (int, error)
├── scripts/
│   └── smoke_test.sh          ← 10-assertion end-to-end smoke test
├── legacy-web/                ← Archived Node/TypeScript workspace (not active)
│   ├── artifacts/             ← Former api-server + mockup-sandbox artifacts
│   ├── lib/                   ← Former shared TS libraries
│   ├── scripts-ts/            ← Former TS-based scripts
│   ├── package.json
│   ├── pnpm-workspace.yaml
│   └── tsconfig*.json
├── go.mod
├── go.sum
├── Makefile
├── LICENSE
└── README.md
```

## Key Design Decisions

- **exec.Run returns `(int, error)`** — no `os.Exit` inside library code; exit code is propagated by `main`.
- **DIGEST_AUTO_APPROVE=1** — env-var escape hatch that bypasses the TUI for CI and smoke tests.
- **Dynamic card width** — `tea.WindowSizeMsg` drives `clamp(termWidth − 12, 36, 80)` content width.
- **Case-insensitive pattern scan** — full command is lowercased before matching `dangerousPatterns`.
- **Output suppression detection** — `>/dev/null`, `2>/dev/null`, `&>/dev/null` flagged as HIGH risk.

## Makefile Targets

| Target | Description |
|--------|-------------|
| `make build` | Compile `./cmd/digest` → `./digest` |
| `make test` | `go test -race -count=1 ./...` |
| `make vet` | `go vet ./...` |
| `make tidy` | `go mod tidy` |
| `make install` | Install to `/usr/local/bin` (override with `PREFIX=`) |
| `make smoke-test` | Build + run `scripts/smoke_test.sh` |
| `make clean` | Remove compiled binary |

## Running

```bash
make build
./digest rm -rf ./tmp
./digest npm install express
DIGEST_AUTO_APPROVE=1 ./digest echo success   # CI / non-interactive
```
