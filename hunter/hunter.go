package hunter

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

var DefaultFlagNames = []string{
	"flag.txt",
	"user.txt",
	"root.txt",
	"proof.txt",
	"local.txt",
	"network-secret.txt",
	"credentials.txt",
	"secret.txt",
}

type Config struct {
	Deep       bool
	ExtraNames []string
	Pattern    string
	Dir        string
	MaxDepth   int
}

type Result struct {
	Path        string `json:"path"`
	Contents    string `json:"contents"`
	Type        string `json:"type"`
	Reason      string `json:"reason,omitempty"`
	Permissions string `json:"permissions,omitempty"`
}

func Hunt(cfg Config) []Result {
	initScanner()

	names := make([]string, len(DefaultFlagNames))
	copy(names, DefaultFlagNames)
	names = append(names, cfg.ExtraNames...)

	var customRe *regexp.Regexp
	if cfg.Pattern != "" {
		re, err := regexp.Compile(cfg.Pattern)
		if err == nil {
			customRe = re
		}
	}

	var results []Result
	seen := make(map[string]bool)

	addResult := func(r Result) {
		if !seen[r.Path] {
			seen[r.Path] = true
			results = append(results, r)
		}
	}

	for _, r := range scanEnvironment() {
		addResult(r)
	}

	var dirs []string
	if cfg.Dir != "" {
		dirs = []string{cfg.Dir}
	} else if cfg.Deep {
		if runtime.GOOS == "windows" {
			dirs = []string{"C:\\"}
		} else {
			dirs = []string{"/"}
		}
	} else {
		dirs = getPriorityPaths()
	}

	for _, dir := range dirs {
		for _, d := range expandGlobs(dir) {
			scanDir(d, names, customRe, cfg, seen, addResult)
		}
	}

	return results
}

func expandGlobs(pattern string) []string {
	if !strings.ContainsAny(pattern, "*?[") {
		return []string{pattern}
	}
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return nil
	}
	return matches
}

func scanDir(dir string, names []string, customRe *regexp.Regexp, cfg Config, seen map[string]bool, addResult func(Result)) {
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
			if cfg.MaxDepth > 0 {
				rel, relErr := filepath.Rel(dir, path)
				if relErr == nil && rel != "." {
					depth := strings.Count(rel, string(os.PathSeparator)) + 1
					if depth > cfg.MaxDepth {
						return filepath.SkipDir
					}
				}
			}
			base := d.Name()
			if base == ".git" || base == "node_modules" || base == "__pycache__" || base == ".svn" {
				return filepath.SkipDir
			}
			if runtime.GOOS != "windows" {
				if path == "/proc" || path == "/sys" || path == "/dev" || path == "/run" || path == "/snap" {
					return filepath.SkipDir
				}
			}
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}

		fname := d.Name()
		perms := info.Mode().String()

		for _, name := range names {
			if strings.EqualFold(fname, name) {
				addResult(Result{
					Path:        path,
					Contents:    readDisplay(path, info.Size()),
					Type:        "FLAG",
					Permissions: perms,
				})
				break
			}
		}

		if info.Size() > 0 && info.Size() <= maxReadSize {
			if matched, pat := matchCTFPatterns(path, info.Size()); matched && !seen[path] {
				addResult(Result{
					Path:        path,
					Contents:    readDisplay(path, info.Size()),
					Type:        "PATTERN",
					Reason:      "matched: " + pat,
					Permissions: perms,
				})
			}

			if customRe != nil && !seen[path] {
				if matchCustomPattern(path, info.Size(), customRe) {
					addResult(Result{
						Path:        path,
						Contents:    readDisplay(path, info.Size()),
						Type:        "PATTERN",
						Reason:      "matched: " + cfg.Pattern,
						Permissions: perms,
					})
				}
			}
		}

		if isSuspicious(path, info) && !seen[path] {
			contents := readDisplay(path, info.Size())
			reason := detectReason(path, info, contents)
			if reason != "" {
				addResult(Result{
					Path:        path,
					Contents:    contents,
					Type:        "SUSPICIOUS",
					Reason:      reason,
					Permissions: perms,
				})
			}
		}

		for _, r := range scanADS(path) {
			if !seen[r.Path] {
				r.Permissions = perms
				addResult(r)
			}
		}

		if !seen[path] {
			for _, r := range checkEncodedContent(path, info.Size()) {
				r.Permissions = perms
				addResult(r)
			}
		}

		return nil
	})
}

func scanEnvironment() []Result {
	var results []Result

	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 || parts[1] == "" {
			continue
		}
		key, value := parts[0], parts[1]

		keyLower := strings.ToLower(key)
		flagKey := strings.Contains(keyLower, "flag") ||
			strings.Contains(keyLower, "secret") ||
			strings.Contains(keyLower, "ctf") ||
			strings.Contains(keyLower, "proof")

		patternMatch := false
		for _, re := range compiledCTF {
			if re.MatchString(value) {
				patternMatch = true
				break
			}
		}

		hashMatch := hashPattern.MatchString(strings.TrimSpace(value))

		if !flagKey && !patternMatch && !hashMatch {
			continue
		}

		var reasons []string
		reasons = append(reasons, "environment variable")
		if flagKey {
			reasons = append(reasons, "flag-related key")
		}
		if patternMatch {
			reasons = append(reasons, "CTF flag pattern")
		}
		if hashMatch {
			reasons = append(reasons, "hash-like value")
		}

		results = append(results, Result{
			Path:     "$" + key,
			Contents: value,
			Type:     "ENV",
			Reason:   strings.Join(reasons, ", "),
		})
	}

	return results
}
