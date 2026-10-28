package hunter

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

var hashPattern = regexp.MustCompile(`^[a-fA-F0-9]{32,64}\s*$`)

var privilegedDirs []string

func init() {
	if runtime.GOOS == "windows" {
		privilegedDirs = []string{
			`C:\Users\Administrator`,
			`C:\Users\Administrator\Desktop`,
			`C:\Users\Administrator\Documents`,
		}
	} else {
		privilegedDirs = []string{
			"/root",
			"/home",
			"/opt",
		}
	}
}

func isSuspicious(path string, info os.FileInfo) bool {
	if info.Size() > 100 || info.Size() == 0 {
		return false
	}
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".txt" && ext != "" {
		if ext != ".md" && ext != ".flag" && ext != ".secret" {
			return false
		}
	}
	if ext == "" {
		base := filepath.Base(path)
		if strings.HasPrefix(base, ".") {
			return true
		}
		return false
	}
	return inPrivilegedDir(path)
}

func inPrivilegedDir(path string) bool {
	for _, d := range privilegedDirs {
		if strings.HasPrefix(strings.ToLower(path), strings.ToLower(d)) {
			return true
		}
	}
	return false
}

func detectReason(path string, info os.FileInfo, contents string) string {
	if contents == "" || contents == "<binary>" {
		return ""
	}
	trimmed := strings.TrimSpace(contents)

	var reasons []string

	if info.Size() < 100 {
		reasons = append(reasons, "small file")
	}

	if hashPattern.MatchString(trimmed) {
		reasons = append(reasons, "hash-like content")
	}

	if inPrivilegedDir(path) {
		reasons = append(reasons, "privileged directory")
	}

	base := filepath.Base(path)
	if strings.HasPrefix(base, ".") {
		reasons = append(reasons, "hidden file")
	}

	if len(reasons) == 0 {
		return ""
	}
	return strings.Join(reasons, ", ")
}
