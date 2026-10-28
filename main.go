package main

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"time"

	"github.com/XORRav/goreap/hunter"
	"github.com/XORRav/goreap/output"
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
	pattern := flag.String("pattern", "", "Regex pattern to match inside files")
	dir := flag.String("dir", "", "Start search from this directory only")
	noColor := flag.Bool("no-color", false, "Disable colored output")
	quiet := flag.Bool("quiet", false, "Only print found flags, no banner/status")
	jsonOut := flag.Bool("json", false, "Output results as JSON")
	showVersion := flag.Bool("version", false, "Print version and exit")

	flag.Parse()

	if *showVersion {
		fmt.Printf("goreap %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	cfg := hunter.Config{
		Deep:       *deep,
		ExtraNames: names,
		Pattern:    *pattern,
		Dir:        *dir,
	}

	p := output.NewPrinter(*noColor || *jsonOut, *quiet)

	if !*quiet && !*jsonOut {
		p.Banner()
		p.Info("OS detected: %s", runtime.GOOS)
		if u, err := user.Current(); err == nil {
			p.Info("Running as: %s", u.Username)
		}
		if *deep {
			p.Info("Deep scan — crawling entire filesystem...")
		} else if cfg.Dir != "" {
			p.Info("Scanning directory: %s", cfg.Dir)
		} else {
			p.Info("Quick scan — checking common flag locations...")
		}
		fmt.Println()
	}

	start := time.Now()

	results := hunter.Hunt(cfg)

	elapsed := time.Since(start)

	if *jsonOut {
		output.PrintJSON(results)
	} else {
		for _, r := range results {
			p.Result(r)
		}
		if !*quiet {
			fmt.Println()
			p.Info("Scan complete — %d results found in %.2fs", len(results), elapsed.Seconds())
		}
	}

	if len(results) == 0 {
		os.Exit(1)
	}
}
