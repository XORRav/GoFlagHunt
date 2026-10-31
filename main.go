package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"runtime"
	"strings"
	"time"

	"github.com/XORRav/wraithflag/hunter"
	"github.com/XORRav/wraithflag/output"
)

var version = "dev"

type arrayFlag []string

func (a *arrayFlag) String() string { return fmt.Sprintf("%v", *a) }
func (a *arrayFlag) Set(value string) error {
	*a = append(*a, value)
	return nil
}

func main() {
	var names arrayFlag

	deep := flag.Bool("deep", false, "Full filesystem crawl (default: quick common-paths scan)")
	flag.Var(&names, "name", "Additional filename to hunt for (can be repeated)")
	pattern := flag.String("pattern", "", "Additional regex pattern to match inside files")
	dir := flag.String("dir", "", "Start search from this directory only")
	noColor := flag.Bool("no-color", false, "Disable colored output")
	quiet := flag.Bool("quiet", false, "Only print found flags, no banner/status")
	jsonOut := flag.Bool("json", false, "Output results as JSON")
	showVersion := flag.Bool("version", false, "Print version and exit")
	exfil := flag.String("exfil", "", "Write all found flags to this file")
	depth := flag.Int("depth", 0, "Limit directory recursion depth (0 = unlimited)")
	watch := flag.Bool("watch", false, "Keep running and alert when new flag files appear")
	noSuspicious := flag.Bool("no-suspicious", false, "Hide suspicious-file results")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `WraithFlag — Portable post-exploitation flag finder

Usage:
  wraithflag [options]

Options:
  --deep              Full filesystem crawl (default: quick common-paths scan)
  --name <file>       Additional filename to hunt for (repeatable)
  --pattern <regex>   Regex pattern to match inside files
  --dir <path>        Start search from this directory only
  --depth <n>         Limit directory recursion depth (0 = unlimited)
  --exfil <file>      Write all found flags to this file
  --watch             Keep running and alert when new flag files appear
  --no-suspicious     Hide suspicious-file results
  --no-color          Disable colored output
  --quiet             Only print found flags, no banner/status
  --json              Output results as JSON
  --version           Print version and exit
  -h, --help          Show this help

Examples:
  wraithflag                              Quick scan common flag locations
  wraithflag --deep                       Full filesystem crawl
  wraithflag --dir /var/www --depth 3     Scan specific dir with depth limit
  wraithflag --pattern "SECRET_\w+"       Custom regex pattern search
  wraithflag --no-suspicious --exfil /tmp/loot.txt
`)
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("wraithflag %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	p := output.NewPrinter(*noColor || *jsonOut, *quiet)

	cfg := hunter.Config{
		Deep:         *deep,
		ExtraNames:   names,
		Pattern:      *pattern,
		Dir:          *dir,
		MaxDepth:     *depth,
		NoSuspicious: *noSuspicious,
	}

	if !*quiet && !*jsonOut {
		cfg.OnProgress = func(dir string) {
			p.Info("Scanning: %s", dir)
		}
	}

	if *watch {
		runWatch(cfg, p, *jsonOut, *quiet, *exfil)
		return
	}

	results := runOnce(cfg, p, *jsonOut, *quiet)

	if *exfil != "" {
		writeExfil(*exfil, results, p)
	}

	if len(results) == 0 {
		os.Exit(1)
	}
}

func runOnce(cfg hunter.Config, p *output.Printer, jsonOut, quiet bool) []hunter.Result {
	if !quiet && !jsonOut {
		p.Banner()
		p.Info("OS detected: %s", runtime.GOOS)
		if u, err := user.Current(); err == nil {
			p.Info("Running as: %s", u.Username)
		}
		if cfg.Deep {
			p.Info("Deep scan — crawling entire filesystem...")
		} else if cfg.Dir != "" {
			p.Info("Scanning directory: %s", cfg.Dir)
		} else {
			p.Info("Quick scan — checking common flag locations...")
		}
		fmt.Println()
	}

	start := time.Now()
	results, stats := hunter.Hunt(cfg)
	elapsed := time.Since(start)

	if jsonOut {
		output.PrintJSON(results)
	} else {
		for _, r := range results {
			p.Result(r)
		}
		if !quiet {
			p.Summary(results, stats, elapsed.Seconds())
		}
	}

	return results
}

func runWatch(cfg hunter.Config, p *output.Printer, jsonOut, quiet bool, exfilPath string) {
	if !quiet && !jsonOut {
		p.Banner()
		p.Info("OS detected: %s", runtime.GOOS)
		if u, err := user.Current(); err == nil {
			p.Info("Running as: %s", u.Username)
		}
		p.Info("Watch mode — scanning every 5s (Ctrl+C to stop)...")
		fmt.Println()
	}

	seen := make(map[string]bool)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	results, _ := hunter.Hunt(cfg)
	var allResults []hunter.Result
	for _, r := range results {
		seen[r.Path] = true
		allResults = append(allResults, r)
		if !jsonOut {
			p.Result(r)
		}
	}
	if jsonOut && len(results) > 0 {
		output.PrintJSON(results)
	}
	if !quiet && !jsonOut {
		fmt.Println()
		p.Info("Initial scan: %d results. Watching for new flags...", len(results))
	}

	for {
		select {
		case <-sig:
			if !quiet && !jsonOut {
				fmt.Println()
				p.Info("Watch stopped. Total: %d results found.", len(allResults))
			}
			if exfilPath != "" {
				writeExfil(exfilPath, allResults, p)
			}
			return
		case <-ticker.C:
			newResults, _ := hunter.Hunt(cfg)
			for _, r := range newResults {
				if !seen[r.Path] {
					seen[r.Path] = true
					allResults = append(allResults, r)
					if jsonOut {
						output.PrintJSON([]hunter.Result{r})
					} else {
						p.Result(r)
						if !quiet {
							p.Info("New flag found! Total: %d", len(allResults))
						}
					}
				}
			}
		}
	}
}

func writeExfil(path string, results []hunter.Result, p *output.Printer) {
	var sb strings.Builder
	for _, r := range results {
		sb.WriteString(fmt.Sprintf("[%s] [%d%%] %s\n", r.Type, r.Confidence, r.Path))
		if r.Contents != "" {
			sb.WriteString(fmt.Sprintf("  %s\n", strings.TrimSpace(r.Contents)))
		}
		if r.MatchLine != "" {
			sb.WriteString(fmt.Sprintf("  Match: %s\n", r.MatchLine))
		}
		if r.Reason != "" {
			sb.WriteString(fmt.Sprintf("  Reason: %s\n", r.Reason))
		}
		sb.WriteString("\n")
	}
	err := os.WriteFile(path, []byte(sb.String()), 0644)
	if err != nil {
		p.Info("Failed to write exfil file: %v", err)
		return
	}
	p.Info("Flags written to: %s", path)
}
