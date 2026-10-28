# GOreap

**Portable post-exploitation flag finder written in Go.**

Drop the binary on a box, run it, get your flags. No dependencies, no install, just works.

## Quick Start

Grab the latest binary from [Releases](https://github.com/XORRav/goreap/releases), drop it on the target, and run:

```bash
# Linux
chmod +x goreap-linux-amd64
./goreap-linux-amd64

# Windows
goreap-windows-amd64.exe
```

## What It Does

Hunts for CTF/exam flag files (`user.txt`, `root.txt`, `flag.txt`, etc.) across the filesystem. Checks common flag locations first for speed, then optionally does a full sweep. Reads and displays flag contents when found.

## Features

- **Filename Hunting** — searches for known flag filenames (`flag.txt`, `user.txt`, `root.txt`, `proof.txt`, `local.txt`, `network-secret.txt`, `credentials.txt`, `secret.txt`)
- **Smart Search Order** — hits high-probability locations first (`/root/`, `/home/*/`, admin desktops) before crawling everything
- **Content Pattern Matching** — regex search inside files (e.g. `HTB{.*}`, `FLAG{.*}`)
- **Suspicious File Detection** — finds small files with hash-like content in privileged directories
- **Cross-Platform** — single static binary for Linux and Windows
- **Zero Dependencies** — Go stdlib only

## Usage

```
goreap [flags]

Flags:
  --deep           Full filesystem crawl (default: quick common-paths scan)
  --name string    Additional filename to hunt for (can be repeated)
  --pattern string Regex pattern to match inside files
  --dir string     Start search from this directory only
  --no-color       Disable colored output
  --quiet          Only print found flags, no banner/status
  --json           Output results as JSON
  --version        Print version and exit
  -h, --help       Help
```

### Examples

```bash
# Quick scan - checks common flag locations
./goreap

# Deep scan - crawls entire filesystem
./goreap --deep

# Hunt for specific filenames
./goreap --name secret_key.txt --name creds.txt

# Scan a specific directory
./goreap --dir /var/www/html

# Pattern match inside files
./goreap --pattern "HTB\{.*\}"

# Quiet JSON output for scripting
./goreap --quiet --json
```

## Output

```
╔═══════════════════════════════════════╗
║          G O r e a p                  ║
║       Post-Exploitation Loot          ║
╚═══════════════════════════════════════╝

[*] OS detected: linux
[*] Running as: root
[*] Quick scan - checking common flag locations...

[FLAG] /root/root.txt
       Contents: d41d8cd98f00b204e9800998ecf8427e

[FLAG] /home/svc_user/user.txt
       Contents: 7c6a180b36896a65c4e635714120a536

[SUSPICIOUS] /opt/.secret
       Contents: 5f4dcc3b5aa765d61d8327deb882cf99
       Reason: small file, hash-like content

[*] Scan complete - 3 results found in 0.42s
```

## Build From Source

Requires Go 1.22+.

```bash
# Clone
git clone https://github.com/XORRav/goreap.git
cd goreap

# Build for current OS
go build -ldflags="-s -w" -o goreap .

# Cross-compile
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o goreap-linux-amd64 .
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o goreap-windows-amd64.exe .
```

## Releasing

Push a version tag and GitHub Actions builds + publishes binaries automatically:

```bash
git tag v1.0.0
git push origin v1.0.0
```

## License

MIT
