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

var noisyDirs = []string{
	".cache", ".cargo", ".local/lib", ".local/share/pipx",
	".local/share/gem", ".local/share/npm",
	"site-packages", "dist-info", "node_modules",
	"__pycache__", ".npm", ".nvm", ".rustup",
	"nuclei-templates", "go-build", ".gradle",
	".m2", ".pip", ".venv", "venv",
}

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

func isNoisyPath(path string) bool {
	lower := strings.ToLower(path)
	for _, d := range noisyDirs {
		if strings.Contains(lower, d) {
			return true
		}
	}
	return false
}

func isSuspicious(path string, info os.FileInfo) bool {
	if info.Size() > 100 || info.Size() == 0 {
		return false
	}

	if isNoisyPath(path) {
		return false
	}

	ext := strings.ToLower(filepath.Ext(path))
	base := filepath.Base(path)

	if ext == "" && strings.HasPrefix(base, ".") {
		return true
	}

	if ext != ".txt" && ext != ".flag" && ext != ".secret" {
		return false
	}

	if !inPrivilegedDir(path) {
		return false
	}

	return true
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

	isHash := hashPattern.MatchString(trimmed)
	isHidden := strings.HasPrefix(filepath.Base(path), ".")
	isPriv := inPrivilegedDir(path)

	if !isHash && !isHidden {
		return ""
	}

	if info.Size() < 100 {
		reasons = append(reasons, "small file")
	}
	if isHash {
		reasons = append(reasons, "hash-like content")
	}
	if isPriv {
		reasons = append(reasons, "privileged directory")
	}
	if isHidden {
		reasons = append(reasons, "hidden file")
	}

	if len(reasons) == 0 {
		return ""
	}
	return strings.Join(reasons, ", ")
}
