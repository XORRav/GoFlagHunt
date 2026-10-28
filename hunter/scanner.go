package hunter

import (
	"os"
	"regexp"
)

const maxReadSize = 1024 * 1024

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

type cachedFile struct {
	data []byte
	skip bool
}

var (
	cache       map[string]*cachedFile
	compiledCTF []*regexp.Regexp
)

func initScanner() {
	cache = make(map[string]*cachedFile)
	compiledCTF = nil
	for _, p := range DefaultCTFPatterns {
		if re, err := regexp.Compile(p); err == nil {
			compiledCTF = append(compiledCTF, re)
		}
	}
}

func readRaw(path string, size int64) ([]byte, bool) {
	if cf, ok := cache[path]; ok {
		return cf.data, cf.skip
	}
	cf := &cachedFile{}
	if size > maxReadSize || size == 0 {
		cf.skip = true
		cache[path] = cf
		return nil, true
	}
	data, err := os.ReadFile(path)
	if err != nil {
		cf.skip = true
		cache[path] = cf
		return nil, true
	}
	for _, b := range data {
		if b == 0 {
			cf.skip = true
			cache[path] = cf
			return nil, true
		}
	}
	cf.data = data
	cache[path] = cf
	return data, false
}

func readDisplay(path string, size int64) string {
	data, skip := readRaw(path, size)
	if skip || data == nil {
		return ""
	}
	s := string(data)
	if len(s) > 512 {
		s = s[:512] + "..."
	}
	return s
}

func matchCustomPattern(path string, size int64, re *regexp.Regexp) bool {
	data, skip := readRaw(path, size)
	if skip || data == nil {
		return false
	}
	return re.Match(data)
}

func matchCTFPatterns(path string, size int64) (bool, string) {
	data, skip := readRaw(path, size)
	if skip || data == nil {
		return false, ""
	}
	for i, re := range compiledCTF {
		if re.Match(data) {
			return true, DefaultCTFPatterns[i]
		}
	}
	return false, ""
}
