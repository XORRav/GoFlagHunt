package hunter

import (
	"os"
	"regexp"
)

const maxReadSize = 1024 * 1024 // 1MB

func readFileContents(path string, size int64) string {
	if size > maxReadSize || size == 0 {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, b := range data {
		if b == 0 {
			return "<binary>"
		}
	}
	s := string(data)
	if len(s) > 512 {
		s = s[:512] + "..."
	}
	return s
}

func matchPattern(path string, size int64, pattern string) bool {
	if size > maxReadSize || size == 0 {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, b := range data {
		if b == 0 {
			return false
		}
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.Match(data)
}
