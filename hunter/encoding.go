package hunter

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
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
				Path:       path,
				Contents:   decoded,
				Type:       "ENCODED",
				Reason:     "base64-encoded flag content",
				Confidence: 80,
			})
		}
	}

	if decoded := tryHex(content); decoded != "" {
		if matchesFlag(decoded) {
			results = append(results, Result{
				Path:       path,
				Contents:   decoded,
				Type:       "ENCODED",
				Reason:     "hex-encoded flag content",
				Confidence: 80,
			})
		}
	}

	if decoded := tryROT13(content); decoded != "" {
		if matchesFlag(decoded) {
			results = append(results, Result{
				Path:       path,
				Contents:   decoded,
				Type:       "ENCODED",
				Reason:     "ROT13-encoded flag content",
				Confidence: 75,
			})
		}
	}

	if decoded := tryURLDecode(content); decoded != "" {
		if matchesFlag(decoded) {
			results = append(results, Result{
				Path:       path,
				Contents:   decoded,
				Type:       "ENCODED",
				Reason:     "URL-encoded flag content",
				Confidence: 75,
			})
		}
	}

	if reversed := tryReverse(content); reversed != "" {
		if matchesCTFPattern(reversed) {
			results = append(results, Result{
				Path:       path,
				Contents:   reversed,
				Type:       "ENCODED",
				Reason:     "reversed flag content",
				Confidence: 70,
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

func tryROT13(s string) string {
	hasLetter := false
	decoded := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			hasLetter = true
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			hasLetter = true
			return 'A' + (r-'A'+13)%26
		}
		return r
	}, s)
	if !hasLetter {
		return ""
	}
	return decoded
}

func tryURLDecode(s string) string {
	if !strings.Contains(s, "%") {
		return ""
	}
	decoded, err := url.QueryUnescape(s)
	if err != nil || decoded == s {
		return ""
	}
	return decoded
}

func tryReverse(s string) string {
	runes := []rune(s)
	n := len(runes)
	out := make([]rune, n)
	for i := 0; i < n; i++ {
		out[i] = runes[n-1-i]
	}
	return string(out)
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
	if matchesCTFPattern(decoded) {
		return true
	}
	if hashPattern.MatchString(strings.TrimSpace(decoded)) {
		return true
	}
	return false
}

func matchesCTFPattern(s string) bool {
	for _, re := range compiledCTF {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}
