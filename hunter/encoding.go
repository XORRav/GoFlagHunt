package hunter

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"unicode"
)

func checkEncodedContent(path string, size int64) []Result {
	if size > maxEncodeSize || size == 0 {
		return nil
	}
	data, skip := readFileSafe(path, maxEncodeSize)
	if skip {
		return nil
	}

	content := strings.TrimSpace(string(data))
	if len(content) < 8 || len(content) > 2048 {
		return nil
	}

	var results []Result

	if decoded := tryBase64(content); decoded != "" {
		if matchesFlag(decoded) {
			results = append(results, Result{
				Path:     path,
				Contents: decoded,
				Type:     "ENCODED",
				Reason:   "base64-encoded flag content",
			})
		}
	}

	if decoded := tryHex(content); decoded != "" {
		if matchesFlag(decoded) {
			results = append(results, Result{
				Path:     path,
				Contents: decoded,
				Type:     "ENCODED",
				Reason:   "hex-encoded flag content",
			})
		}
	}

	return results
}

func tryBase64(s string) string {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			return ""
		}
	}
	if !isPrintable(decoded) {
		return ""
	}
	return string(decoded)
}

func tryHex(s string) string {
	if len(s)%2 != 0 {
		return ""
	}
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return ""
	}
	if !isPrintable(decoded) {
		return ""
	}
	return string(decoded)
}

func isPrintable(data []byte) bool {
	for _, b := range data {
		r := rune(b)
		if !unicode.IsPrint(r) && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}

func matchesFlag(decoded string) bool {
	for _, re := range compiledCTF {
		if re.MatchString(decoded) {
			return true
		}
	}
	if hashPattern.MatchString(strings.TrimSpace(decoded)) {
		return true
	}
	return false
}
