package hunter

import (
	"os"
	"path/filepath"
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
}

type Result struct {
	Path     string `json:"path"`
	Contents string `json:"contents"`
	Type     string `json:"type"`
	Reason   string `json:"reason,omitempty"`
}

func Hunt(cfg Config) []Result {
	names := make([]string, len(DefaultFlagNames))
	copy(names, DefaultFlagNames)
	names = append(names, cfg.ExtraNames...)

	var results []Result
	seen := make(map[string]bool)

	addResult := func(r Result) {
		if !seen[r.Path] {
			seen[r.Path] = true
			results = append(results, r)
		}
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
		expanded := expandGlobs(dir)
		for _, d := range expanded {
			scanDir(d, names, cfg, seen, addResult)
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

func scanDir(dir string, names []string, cfg Config, seen map[string]bool, addResult func(Result)) {
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
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

		for _, name := range names {
			if strings.EqualFold(fname, name) {
				contents := readFileContents(path, info.Size())
				addResult(Result{
					Path:     path,
					Contents: contents,
					Type:     "FLAG",
				})
				break
			}
		}

		if cfg.Pattern != "" {
			if matchPattern(path, info.Size(), cfg.Pattern) {
				contents := readFileContents(path, info.Size())
				if !seen[path] {
					addResult(Result{
						Path:     path,
						Contents: contents,
						Type:     "PATTERN",
						Reason:   "matched pattern: " + cfg.Pattern,
					})
				}
			}
		}

		if isSuspicious(path, info) {
			contents := readFileContents(path, info.Size())
			reason := detectReason(path, info, contents)
			if reason != "" && !seen[path] {
				addResult(Result{
					Path:     path,
					Contents: contents,
					Type:     "SUSPICIOUS",
					Reason:   reason,
				})
			}
		}

		return nil
	})
}
