package output

import (
	"fmt"
	"strings"
	"sync"

	"github.com/XORRav/wraithflag/hunter"
)

const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
	colorWhite   = "\033[37m"
)

type Printer struct {
	noColor bool
	quiet   bool
	mu      sync.Mutex
}

func NewPrinter(noColor, quiet bool) *Printer {
	return &Printer{noColor: noColor, quiet: quiet}
}

func (p *Printer) c(color, text string) string {
	if p.noColor {
		return text
	}
	return color + text + colorReset
}

func (p *Printer) Banner() {
	p.mu.Lock()
	defer p.mu.Unlock()
	banner := `
` + p.c(colorCyan, `╔═══════════════════════════════════════╗`) + `
` + p.c(colorCyan, `║`) + p.c(colorBold+colorGreen, `          W R A I T H F L A G`) + p.c(colorCyan, `║`) + `
` + p.c(colorCyan, `║`) + p.c(colorGreen, `       Post-Exploitation Loot        `) + p.c(colorCyan, `║`) + `
` + p.c(colorCyan, `╚═══════════════════════════════════════╝`) + `
`
	fmt.Println(banner)
}

func (p *Printer) Info(format string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Printf("%s %s\n", p.c(colorCyan, "[*]"), fmt.Sprintf(format, args...))
}

func (p *Printer) Result(r hunter.Result) {
	p.mu.Lock()
	defer p.mu.Unlock()

	tag, color := typeTag(r.Type)
	confStr := fmt.Sprintf("[%d%%]", r.Confidence)

	fmt.Printf("\n%s %s %s\n",
		p.c(colorBold+color, tag),
		p.c(color, r.Path),
		p.c(colorDim, confStr),
	)

	if r.Contents != "" {
		fmt.Printf("       Contents: %s\n", strings.TrimSpace(r.Contents))
	}
	if r.MatchLine != "" {
		fmt.Printf("       Match:    %s\n", p.c(colorYellow, r.MatchLine))
	}
	if r.Permissions != "" {
		fmt.Printf("       Perms:    %s\n", p.c(colorCyan, r.Permissions))
	}
	if r.Reason != "" {
		fmt.Printf("       Reason:   %s\n", p.c(colorYellow, r.Reason))
	}
}

func (p *Printer) Summary(results []hunter.Result, stats hunter.Stats, elapsed float64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	counts := make(map[string]int)
	for _, r := range results {
		counts[r.Type]++
	}

	types := []struct {
		name  string
		color string
	}{
		{"FLAG", colorGreen},
		{"PATTERN", colorYellow},
		{"ENCODED", colorMagenta},
		{"ARCHIVE", colorMagenta},
		{"ADS", colorMagenta},
		{"REGISTRY", colorCyan},
		{"ENV", colorCyan},
		{"SUSPICIOUS", colorRed},
	}

	fmt.Printf("\n%s\n", p.c(colorCyan, "═══════════════════════════════════════"))
	fmt.Printf(" %s\n", p.c(colorBold+colorWhite, "SUMMARY"))
	fmt.Printf("%s\n", p.c(colorCyan, "═══════════════════════════════════════"))

	col := 0
	for _, t := range types {
		n := counts[t.name]
		if n > 0 {
			fmt.Printf(" %s %s",
				p.c(colorBold+t.color, fmt.Sprintf("%-11s", t.name+":")),
				p.c(colorBold, fmt.Sprintf("%-4d", n)),
			)
			col++
			if col%3 == 0 {
				fmt.Println()
			}
		}
	}
	if col%3 != 0 {
		fmt.Println()
	}

	fmt.Printf("%s\n", p.c(colorCyan, "───────────────────────────────────────"))
	fmt.Printf(" Total: %s in %.2fs\n",
		p.c(colorBold, fmt.Sprintf("%d results", len(results))),
		elapsed,
	)
	fmt.Printf(" Dirs scanned: %d\n", stats.DirsScanned)
	if stats.PermDenied > 0 {
		fmt.Printf(" Permission denied: %s\n",
			p.c(colorRed, fmt.Sprintf("%d", stats.PermDenied)),
		)
	}
	fmt.Printf("%s\n", p.c(colorCyan, "═══════════════════════════════════════"))
}

func typeTag(t string) (string, string) {
	switch t {
	case "FLAG":
		return "[FLAG]", colorGreen
	case "PATTERN":
		return "[PATTERN]", colorYellow
	case "SUSPICIOUS":
		return "[SUSPICIOUS]", colorRed
	case "ENV":
		return "[ENV]", colorCyan
	case "ADS":
		return "[ADS]", colorMagenta
	case "ENCODED":
		return "[ENCODED]", colorMagenta
	case "ARCHIVE":
		return "[ARCHIVE]", colorMagenta
	case "REGISTRY":
		return "[REGISTRY]", colorCyan
	default:
		return "[" + t + "]", colorWhite
	}
}
