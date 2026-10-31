//go:build windows

package hunter

import (
	"context"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var regValueLine = regexp.MustCompile(`^\s+(\S+)\s+(REG_\w+)\s+(.+)$`)

func scanRegistry() []Result {
	paths := []string{
		`HKLM\SOFTWARE\CTF`,
		`HKLM\SOFTWARE\Flag`,
		`HKLM\SOFTWARE\Secret`,
		`HKLM\SOFTWARE\Flags`,
		`HKLM\SOFTWARE\Challenge`,
		`HKCU\SOFTWARE\CTF`,
		`HKCU\SOFTWARE\Flag`,
		`HKCU\SOFTWARE\Secret`,
		`HKCU\SOFTWARE\Flags`,
		`HKCU\SOFTWARE\Challenge`,
		`HKCU\Environment`,
		`HKLM\SYSTEM\CurrentControlSet\Services\FlagService`,
	}

	var results []Result
	seen := make(map[string]bool)

	for _, p := range paths {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out, err := exec.CommandContext(ctx, "reg", "query", p, "/s").Output()
		cancel()
		if err != nil {
			continue
		}
		for _, r := range parseRegOutput(string(out)) {
			key := r.key + `\` + r.name
			if seen[key] {
				continue
			}
			seen[key] = true

			value := strings.TrimSpace(r.value)
			if value == "" {
				continue
			}

			nameLower := strings.ToLower(r.name)
			keyLower := strings.ToLower(r.key)
			isFlagRelated := strings.Contains(nameLower, "flag") ||
				strings.Contains(nameLower, "secret") ||
				strings.Contains(nameLower, "ctf") ||
				strings.Contains(keyLower, "flag") ||
				strings.Contains(keyLower, "secret") ||
				strings.Contains(keyLower, "ctf")

			patternMatch := false
			for _, re := range compiledCTF {
				if re.MatchString(value) {
					patternMatch = true
					break
				}
			}

			hashMatch := hashPattern.MatchString(value)

			if !isFlagRelated && !patternMatch && !hashMatch {
				continue
			}

			results = append(results, Result{
				Path:       "REG:" + r.key + " -> " + r.name,
				Contents:   value,
				Type:       "REGISTRY",
				Reason:     "registry value: " + r.regType,
				Confidence: 70,
			})
		}
	}

	return results
}

type regEntry struct {
	key     string
	name    string
	regType string
	value   string
}

func parseRegOutput(output string) []regEntry {
	var entries []regEntry
	var currentKey string

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}

		if !strings.HasPrefix(line, " ") && strings.Contains(line, `\`) {
			currentKey = strings.TrimSpace(line)
			continue
		}

		matches := regValueLine.FindStringSubmatch(line)
		if matches != nil && currentKey != "" {
			entries = append(entries, regEntry{
				key:     currentKey,
				name:    matches[1],
				regType: matches[2],
				value:   matches[3],
			})
		}
	}
	return entries
}
