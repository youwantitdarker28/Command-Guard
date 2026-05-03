# Workspace

## Overview

pnpm workspace monorepo using TypeScript. Each package manages its own dependencies.
Also contains a standalone Go CLI tool (`digest/`).

## Stack

- **Monorepo tool**: pnpm workspaces
- **Node.js version**: 24
- **Package manager**: pnpm
- **TypeScript version**: 5.9
- **API framework**: Express 5
- **Database**: PostgreSQL + Drizzle ORM
- **Validation**: Zod (`zod/v4`), `drizzle-zod`
- **API codegen**: Orval (from OpenAPI spec)
- **Build**: esbuild (CJS bundle)
- **Go version**: 1.21

## Key Commands

- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- `pnpm --filter @workspace/api-server run dev` — run API server locally

See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details.

## Digest CLI Tool (`digest/`)

A Go TUI command wrapper using Bubble Tea + Lip Gloss.

### Build

```bash
cd digest && go build -o digest .
# or
cd digest && make build
```

### Install to PATH

```bash
cd digest && make install
```

### Usage

```bash
digest <command> [args...]

# Examples:
digest rm -rf ./tmp           # HIGH risk
digest sudo apt update        # HIGH risk
digest git push --force       # HIGH risk
digest mv old.txt new.txt     # MEDIUM risk
digest ls -la                 # LOW risk
```

### Risk Classification
- **HIGH**: `rm`, `sudo`, `chmod`, `chown`, `dd`, `mkfs`, `shred`, `fdisk`, `kill`, `killall`, `pkill`, `truncate`, `git push --force`, `npm publish`
- **LOW**: `ls`, `cat`, `grep`, `find`, `git`, `pwd`, `echo`, `ps`, `df`, `curl`, `wget`, and other read-only commands
- **MEDIUM**: `mv`, `cp`, `mkdir`, `tar`, `apt`, `npm`, `docker`, `ssh`, and all unrecognized commands

### Key Bindings
- `← →` or `h l` — navigate buttons
- `Tab` — toggle selection
- `Enter` — confirm
- `q` / `Esc` / `Ctrl+C` — quit (same as Abort)
