package hunter

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	maxReadSize    = 1024 * 1024 // 1MB — for confirmed flag files by name
	maxPatternSize = 100 * 1024  // 100KB — for pattern scanning
	maxEncodeSize  = 10 * 1024   // 10KB — for encoded content detection
)

var DefaultCTFPatterns = []string{
	`HTB\{[^}]+\}`,
	`FLAG\{[^}]+\}`,
	`THM\{[^}]+\}`,
	`CPTS\{[^}]+\}`,
	`CTF\{[^}]+\}`,
	`flag\{[^}]+\}`,
	`OSCP\{[^}]+\}`,
	`PNPT\{[^}]+\}`,
}

var skipExts = map[string]bool{
	".so": true, ".o": true, ".a": true, ".ko": true,
	".gz": true, ".tar": true, ".zip": true, ".bz2": true, ".xz": true, ".zst": true,
	".jar": true, ".war": true, ".deb": true, ".rpm": true,
	".pyc": true, ".class": true, ".whl": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".bmp": true, ".ico": true, ".svg": true,
	".mp3": true, ".mp4": true, ".avi": true, ".mkv": true, ".wav": true, ".flac": true,
	".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true, ".pptx": true,
	".sqlite": true, ".db": true, ".cache": true,
	".exe": true, ".dll": true, ".elf": true, ".bin": true,
}

var compiledCTF []*regexp.Regexp

func initScanner() {
	compiledCTF = nil
	for _, p := range DefaultCTFPatterns {
		if re, err := regexp.Compile(p); err == nil {
			compiledCTF = append(compiledCTF, re)
		}
	}
}

func shouldSkipContent(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return skipExts[ext]
}

func readFileSafe(path string, maxSize int64) ([]byte, bool) {
	if maxSize <= 0 {
		return nil, true
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, true
	}
	if int64(len(data)) > maxSize {
		return nil, true
	}
	for _, b := range data {
		if b == 0 {
			return nil, true
		}
	}
	return data, false
}

func readDisplay(path string, size int64) string {
	if size > maxReadSize || size == 0 {
		return ""
	}
	data, skip := readFileSafe(path, maxReadSize)
	if skip {
		return ""
	}
	s := string(data)
	if len(s) > 512 {
		s = s[:512] + "..."
	}
	return s
}

func matchCustomPattern(path string, size int64, re *regexp.Regexp) bool {
	if size > maxPatternSize || size == 0 {
		return false
	}
	data, skip := readFileSafe(path, maxPatternSize)
	if skip {
		return false
	}
	return re.Match(data)
}

func matchCTFPatterns(path string, size int64) (bool, string) {
	if size > maxPatternSize || size == 0 {
		return false, ""
	}
	data, skip := readFileSafe(path, maxPatternSize)
	if skip {
		return false, ""
	}
	for i, re := range compiledCTF {
		if re.Match(data) {
			return true, DefaultCTFPatterns[i]
		}
	}
	return false, ""
}
