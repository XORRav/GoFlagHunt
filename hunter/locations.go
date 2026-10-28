package hunter

import "runtime"

func getPriorityPaths() []string {
	if runtime.GOOS == "windows" {
		return windowsPaths()
	}
	return linuxPaths()
}

func linuxPaths() []string {
	return []string{
		"/root",
		"/home/*",
		"/home/*/Desktop",
		"/home/*/Documents",
		"/opt",
		"/tmp",
		"/var",
		"/srv",
	}
}

func windowsPaths() []string {
	return []string{
		`C:\Users\Administrator\Desktop`,
		`C:\Users\Administrator\Documents`,
		`C:\Users\*\Desktop`,
		`C:\Users\*\Documents`,
		`C:\`,
		`C:\inetpub`,
		`C:\xampp`,
	}
}
