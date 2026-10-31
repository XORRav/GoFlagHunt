package hunter

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
	Deep         bool
	ExtraNames   []string
	Pattern      string
	Dir          string
	MaxDepth     int
	NoSuspicious bool
	OnProgress   func(string)
}

type Result struct {
	Path        string `json:"path"`
	Contents    string `json:"contents"`
	Type        string `json:"type"`
	Reason      string `json:"reason,omitempty"`
	Permissions string `json:"permissions,omitempty"`
	Confidence  int    `json:"confidence"`
	MatchLine   string `json:"match_line,omitempty"`
}

type Stats struct {
	PermDenied  int32
	DirsScanned int32
}

func Hunt(cfg Config) ([]Result, Stats) {
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

	var (
		results []Result
		seen    = make(map[string]bool)
		mu      sync.Mutex
		wg      sync.WaitGroup
		stats   Stats
	)

	addResult := func(r Result) {
		mu.Lock()
		defer mu.Unlock()
		if !seen[r.Path] {
			seen[r.Path] = true
			results = append(results, r)
		}
	}

	isSeen := func(path string) bool {
		mu.Lock()
		defer mu.Unlock()
		return seen[path]
	}

	for _, r := range scanEnvironment() {
		addResult(r)
	}

	for _, r := range scanRegistry() {
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

	var walkedPaths []string
	var walkedMu sync.Mutex

	sem := make(chan struct{}, runtime.NumCPU())

	for _, dir := range dirs {
		for _, d := range expandGlobs(dir) {
			absD, err := filepath.Abs(d)
			if err != nil {
				absD = d
			}

			walkedMu.Lock()
			skip := false
			for _, w := range walkedPaths {
				if absD == w || strings.HasPrefix(absD, w+string(os.PathSeparator)) {
					skip = true
					break
				}
			}
			if skip {
				walkedMu.Unlock()
				continue
			}
			walkedPaths = append(walkedPaths, absD)
			walkedMu.Unlock()

			wg.Add(1)
			sem <- struct{}{}
			go func(d string) {
				defer wg.Done()
				defer func() { <-sem }()

				if cfg.OnProgress != nil {
					cfg.OnProgress(d)
				}
				atomic.AddInt32(&stats.DirsScanned, 1)
				scanDir(d, names, customRe, cfg, isSeen, addResult, &stats.PermDenied)
			}(d)
		}
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		if results[i].Confidence != results[j].Confidence {
			return results[i].Confidence > results[j].Confidence
		}
		return results[i].Path < results[j].Path
	})

	return results, stats
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

func scanDir(dir string, names []string, customRe *regexp.Regexp, cfg Config, isSeen func(string) bool, addResult func(Result), permDenied *int32) {
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsPermission(err) {
				atomic.AddInt32(permDenied, 1)
			}
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

		info, infoErr := d.Info()
		if infoErr != nil {
			return nil
		}

		fname := d.Name()
		perms := info.Mode().String()
		readPath := path
		displayPath := path

		if d.Type()&os.ModeSymlink != 0 {
			target, evalErr := filepath.EvalSymlinks(path)
			if evalErr != nil {
				return nil
			}
			tInfo, tErr := os.Stat(target)
			if tErr != nil || tInfo.IsDir() {
				return nil
			}
			info = tInfo
			fname = filepath.Base(target)
			displayPath = path + " -> " + target
			readPath = target
		}

		ext := strings.ToLower(filepath.Ext(fname))

		for _, name := range names {
			if strings.EqualFold(fname, name) {
				addResult(Result{
					Path:        displayPath,
					Contents:    readDisplay(readPath, info.Size()),
					Type:        "FLAG",
					Permissions: perms,
					Confidence:  95,
				})
				break
			}
		}

		if !shouldSkipContent(fname) && info.Size() > 0 {
			if info.Size() <= maxPatternSize {
				if matched, pat, matchLine := matchCTFPatterns(readPath, info.Size()); matched && !isSeen(displayPath) {
					addResult(Result{
						Path:        displayPath,
						Contents:    readDisplay(readPath, info.Size()),
						Type:        "PATTERN",
						Reason:      "matched: " + pat,
						Permissions: perms,
						Confidence:  85,
						MatchLine:   matchLine,
					})
				}

				if customRe != nil && !isSeen(displayPath) {
					if matched, matchLine := matchCustomPattern(readPath, info.Size(), customRe); matched {
						addResult(Result{
							Path:        displayPath,
							Contents:    readDisplay(readPath, info.Size()),
							Type:        "PATTERN",
							Reason:      "matched: " + cfg.Pattern,
							Permissions: perms,
							Confidence:  85,
							MatchLine:   matchLine,
						})
					}
				}
			}

			if !cfg.NoSuspicious && isSuspicious(path, info) && !isSeen(displayPath) {
				contents := readDisplay(readPath, info.Size())
				reason := detectReason(path, info, contents)
				if reason != "" {
					conf := 50
					if strings.Contains(reason, "hash-like") {
						conf = 60
					}
					addResult(Result{
						Path:        displayPath,
						Contents:    contents,
						Type:        "SUSPICIOUS",
						Reason:      reason,
						Permissions: perms,
						Confidence:  conf,
					})
				}
			}

			if info.Size() <= maxEncodeSize && !isSeen(displayPath) {
				for _, r := range checkEncodedContent(readPath, info.Size()) {
					r.Permissions = perms
					r.Path = displayPath
					addResult(r)
				}
			}
		}

		for _, r := range scanADS(path) {
			if !isSeen(r.Path) {
				r.Permissions = perms
				r.Confidence = 90
				addResult(r)
			}
		}

		if isArchive(ext) && !isSeen(displayPath) {
			for _, r := range scanArchive(readPath, info.Size()) {
				addResult(r)
			}
		}

		if isDatabase(ext) && !isSeen(displayPath) {
			for _, r := range scanDatabase(readPath, info.Size()) {
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
			Path:       "$" + key,
			Contents:   value,
			Type:       "ENV",
			Reason:     strings.Join(reasons, ", "),
			Confidence: 75,
		})
	}

	return results
}
