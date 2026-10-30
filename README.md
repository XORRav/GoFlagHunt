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

Hunts for CTF/exam flag files (`user.txt`, `root.txt`, `flag.txt`, etc.) across the filesystem. Checks common flag locations first for speed, then optionally does a full sweep. Reads and displays flag contents when found.

## Features

- **Filename Hunting** — searches for known flag filenames (`flag.txt`, `user.txt`, `root.txt`, `proof.txt`, `local.txt`, `network-secret.txt`, `credentials.txt`, `secret.txt`)
- **Smart Search Order** — hits high-probability locations first (`/root/`, `/home/*/`, admin desktops) before crawling everything
- **Built-in CTF Pattern Matching** — auto-detects common flag formats (`HTB{...}`, `FLAG{...}`, `THM{...}`, `CPTS{...}`, `CTF{...}`, `OSCP{...}`, `PNPT{...}`) without any flags needed
- **Custom Pattern Matching** — regex search inside files via `--pattern` for non-standard flag formats
- **Suspicious File Detection** — finds small files with hash-like content in privileged directories
- **Environment Variable Scanning** — checks env vars for flag-related keys, CTF patterns, and hash-like values
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
  --deep           Full filesystem crawl (default: quick common-paths scan)
  --name string    Additional filename to hunt for (can be repeated)
  --pattern string Regex pattern to match inside files
  --dir string     Start search from this directory only
  --depth int      Limit directory recursion depth (0 = unlimited)
  --exfil string   Write all found flags to this file
  --watch          Keep running and alert when new flag files appear
  --no-color       Disable colored output
  --quiet          Only print found flags, no banner/status
  --json           Output results as JSON
  --version        Print version and exit
  -h, --help       Help
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

# Dump all flags to a file for exfil
./wraithflag --exfil /tmp/loot.txt

# Watch mode - monitor for new flags
./wraithflag --watch

# Quiet JSON output for scripting
./wraithflag --quiet --json

# Scan a network share (Windows)
./wraithflag --dir \\server\share
```

## Output

```
╔═══════════════════════════════════════╗
║      W R A I T H F L A G             ║
║       Post-Exploitation Loot          ║
╚═══════════════════════════════════════╝

[*] OS detected: linux
[*] Running as: root
[*] Quick scan - checking common flag locations...

[ENV] $CTF_FLAG
       Contents: FLAG{3nv_v4r_l34k}
       Reason: environment variable, flag-related key, CTF flag pattern

[FLAG] /root/root.txt
       Contents: d41d8cd98f00b204e9800998ecf8427e
       Perms: -rw-------

[FLAG] /home/svc_user/user.txt
       Contents: 7c6a180b36896a65c4e635714120a536
       Perms: -rw-r--r--

[PATTERN] /opt/app/config.yml
       Contents: HTB{y0u_g0t_th3_fl4g}
       Perms: -rw-r--r--
       Reason: matched: HTB\{[^}]+\}

[SUSPICIOUS] /opt/.secret
       Contents: 5f4dcc3b5aa765d61d8327deb882cf99
       Perms: -rw-------
       Reason: small file, hash-like content, hidden file

[*] Scan complete - 5 results found in 0.42s
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
git tag v2.0.0
git push origin v2.0.0
```

## License

This project is licensed under the [MIT License](LICENSE).
