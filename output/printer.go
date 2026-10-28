package output

import (
	"fmt"
	"strings"

	"github.com/XORRav/goreap/hunter"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

type Printer struct {
	noColor bool
	quiet   bool
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
	banner := `
` + p.c(colorCyan, `╔═══════════════════════════════════════╗`) + `
` + p.c(colorCyan, `║`) + p.c(colorBold+colorGreen, `          G O r e a p                 `) + p.c(colorCyan, `║`) + `
` + p.c(colorCyan, `║`) + p.c(colorGreen, `       Post-Exploitation Loot        `) + p.c(colorCyan, `║`) + `
` + p.c(colorCyan, `╚═══════════════════════════════════════╝`) + `
`
	fmt.Println(banner)
}

func (p *Printer) Info(format string, args ...any) {
	fmt.Printf("%s %s\n", p.c(colorCyan, "[*]"), fmt.Sprintf(format, args...))
}

func (p *Printer) Result(r hunter.Result) {
	switch r.Type {
	case "FLAG":
		fmt.Printf("\n%s %s\n", p.c(colorBold+colorGreen, "[FLAG]"), p.c(colorGreen, r.Path))
	case "PATTERN":
		fmt.Printf("\n%s %s\n", p.c(colorBold+colorYellow, "[PATTERN]"), p.c(colorYellow, r.Path))
	case "SUSPICIOUS":
		fmt.Printf("\n%s %s\n", p.c(colorBold+colorRed, "[SUSPICIOUS]"), p.c(colorRed, r.Path))
	}

	if r.Contents != "" {
		contents := strings.TrimSpace(r.Contents)
		fmt.Printf("       Contents: %s\n", contents)
	}
	if r.Reason != "" {
		fmt.Printf("       Reason: %s\n", p.c(colorYellow, r.Reason))
	}
}
