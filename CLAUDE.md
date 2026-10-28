# GOreap

Portable post-exploitation CTF flag finder written in Go. Stdlib only, no external dependencies.

## Project Structure

```
flaghunter/
├── main.go              # CLI entry point, flag parsing
├── hunter/
│   ├── hunter.go        # Core hunt logic, orchestrates search
│   ├── locations.go     # Platform-specific search paths (linux/windows)
│   ├── scanner.go       # File walking, content reading, pattern matching
│   └── detector.go      # Suspicious file detection (small files, hash-like)
├── output/
│   ├── printer.go       # Colored terminal output, banner
│   └── json.go          # JSON output mode
├── go.mod
├── Makefile
└── CLAUDE.md
```

## Build

```bash
# Native
go build -ldflags="-s -w" -o goreap .

# Cross-compile
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o goreap .
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o goreap.exe .
```

## Design Principles

- Single static binary, zero dependencies (stdlib only)
- Cross-platform: Linux and Windows
- Smart search order: high-probability paths first, full crawl only with --deep
- Binary name: `goreap` / `goreap.exe`
- Module path: `github.com/XORRav/goreap`

## CLI Flags

--deep, --name, --pattern, --dir, --no-color, --quiet, --json
