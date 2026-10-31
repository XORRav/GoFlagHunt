# WraithFlag

**Portable post-exploitation flag finder written in Go.**

Drop the binary on a box, run it, get your flags. No dependencies, no install, just works.

## Quick Start

Grab the latest binary from [Releases](https://github.com/XORRav/wraithflag/releases), drop it on the target, and run:

```bash
# Linux
chmod +x wraithflag-linux-amd64
./wraithflag-linux-amd64

# Windows
wraithflag-windows-amd64.exe
```

## What It Does

Hunts for CTF/exam flag files (`user.txt`, `root.txt`, `flag.txt`, etc.) across the filesystem. Checks common flag locations first for speed, then optionally does a full sweep. Reads and displays flag contents when found. Results are ranked by confidence so you see the most likely flags first.

## Features

- **Filename Hunting** — searches for known flag filenames (`flag.txt`, `user.txt`, `root.txt`, `proof.txt`, `local.txt`, `network-secret.txt`, `credentials.txt`, `secret.txt`)
- **Smart Search Order** — hits high-probability locations first (`/root/`, `/home/*/`, admin desktops) before crawling everything
- **Built-in CTF Pattern Matching** — auto-detects common flag formats (`HTB{...}`, `FLAG{...}`, `THM{...}`, `CPTS{...}`, `CTF{...}`, `OSCP{...}`, `PNPT{...}`) with matching line context
- **Custom Pattern Matching** — regex search inside files via `--pattern` for non-standard flag formats
- **NTFS Alternate Data Streams** — detects flags hidden in ADS (the `hm.txt:root.txt:$DATA` trick), auto-reads hidden stream contents
- **Encoded Flag Detection** — tries base64, hex, ROT13, URL-encoded, and reversed string decoding on file contents
- **Archive Scanning** — looks inside `.zip`, `.tar`, `.tar.gz`, and `.tgz` files for flag files and CTF patterns
- **Database Scanning** — scans raw `.sqlite`/`.db` files for CTF flag patterns
- **Windows Registry Scanning** — checks common registry paths for flag-related values (Windows only)
- **Suspicious File Detection** — finds small files with hash-like content in privileged directories
- **Environment Variable Scanning** — checks env vars for flag-related keys, CTF patterns, and hash-like values
- **Symlink Awareness** — follows and reports symlinked flag files with their targets
- **Concurrent Scanning** — parallel goroutine workers for faster multi-directory scans
- **Path Deduplication** — avoids re-scanning subdirectories already covered by a parent scan
- **Confidence Ranking** — results sorted by confidence score (FLAG 95%, PATTERN 85%, ENCODED 80%, etc.)
- **Progress Indicator** — shows which directory is currently being scanned
- **Result Summary** — colorized summary table with counts by type, timing, and permission denied counter
- **File Permissions** — displays file permissions alongside each result
- **Depth Limiting** — `--depth N` to control how deep the directory crawl goes
- **Watch Mode** — `--watch` to continuously monitor for new flag files appearing
- **Exfil Mode** — `--exfil <file>` to dump all found flags to a single file for easy grab
- **Cross-Platform** — single static binary for Linux and Windows
- **Zero Dependencies** — Go stdlib only

## Usage

```
wraithflag [flags]

Flags:
  --deep              Full filesystem crawl (default: quick common-paths scan)
  --name string       Additional filename to hunt for (can be repeated)
  --pattern string    Regex pattern to match inside files
  --dir string        Start search from this directory only
  --depth int         Limit directory recursion depth (0 = unlimited)
  --exfil string      Write all found flags to this file
  --watch             Keep running and alert when new flag files appear
  --no-suspicious     Hide suspicious-file results
  --no-color          Disable colored output
  --quiet             Only print found flags, no banner/status
  --json              Output results as JSON
  --version           Print version and exit
  -h, --help          Help
```

### Examples

```bash
# Quick scan - checks common flag locations
./wraithflag

# Deep scan - crawls entire filesystem
./wraithflag --deep

# Hunt for specific filenames
./wraithflag --name secret_key.txt --name creds.txt

# Scan a specific directory
./wraithflag --dir /var/www/html

# Limit scan depth
./wraithflag --dir /home --depth 3

# Custom pattern match inside files
./wraithflag --pattern "SECRET_[A-Z0-9]+"

# Skip suspicious results for cleaner output
./wraithflag --no-suspicious

# Dump all flags to a file for exfil
./wraithflag --exfil /tmp/loot.txt

# Watch mode - monitor for new flags
./wraithflag --watch

# Quiet JSON output for scripting
./wraithflag --quiet --json
```

## Output

```
╔═══════════════════════════════════════╗
║          W R A I T H F L A G          ║
║       Post-Exploitation Loot          ║
╚═══════════════════════════════════════╝

[*] OS detected: linux
[*] Running as: root
[*] Quick scan — checking common flag locations...
[*] Scanning: /root/
[*] Scanning: /home/user/

[FLAG] /root/root.txt                                    [95%]
       Contents: d41d8cd98f00b204e9800998ecf8427e
       Perms:    -rw-------

[PATTERN] /opt/app/config.yml                            [85%]
       Contents: HTB{y0u_g0t_th3_fl4g}
       Match:    api_key: HTB{y0u_g0t_th3_fl4g}
       Perms:    -rw-r--r--
       Reason:   matched: HTB\{[^}]+\}

[ENCODED] /tmp/payload.b64                               [80%]
       Contents: FLAG{y0u_d0c0d3d_m3}
       Perms:    -rw-r--r--
       Reason:   base64-encoded flag content

[ARCHIVE] /tmp/backup.zip -> flags/root.txt              [70%]
       Contents: THM{z1pp3d_fl4g}
       Reason:   flag file inside zip

═══════════════════════════════════════
 SUMMARY
═══════════════════════════════════════
 FLAG:       1    PATTERN:    1    ENCODED:    1
 ARCHIVE:    1
───────────────────────────────────────
 Total: 4 results in 0.42s
 Dirs scanned: 8
 Permission denied: 3
═══════════════════════════════════════
```

## Build From Source

Requires Go 1.22+.

```bash
# Clone
git clone https://github.com/XORRav/wraithflag.git
cd wraithflag

# Build for current OS
go build -ldflags="-s -w" -o wraithflag .

# Cross-compile
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o wraithflag-linux-amd64 .
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o wraithflag-windows-amd64.exe .
```

## Releasing

Push a version tag and GitHub Actions builds + publishes binaries automatically:

```bash
git tag v3.0.1
git push origin v3.0.1
```

## Vibe-Coded

This tool was vibe-coded with [Claude Code](https://claude.com/claude-code).

## License

This project is licensed under the [MIT License](LICENSE).
