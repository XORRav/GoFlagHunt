//go:build windows

package hunter

import (
	"os"
	"strings"
	"syscall"
	"unsafe"
)

var (
	modkernel32          = syscall.NewLazyDLL("kernel32.dll")
	procFindFirstStreamW = modkernel32.NewProc("FindFirstStreamW")
	procFindNextStreamW  = modkernel32.NewProc("FindNextStreamW")
	procFindCloseStream  = modkernel32.NewProc("FindClose")
)

type win32FindStreamData struct {
	StreamSize int64
	StreamName [296]uint16
}

func scanADS(path string) []Result {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil
	}

	var data win32FindStreamData
	handle, _, _ := procFindFirstStreamW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		uintptr(unsafe.Pointer(&data)),
		0,
	)

	if handle == uintptr(syscall.InvalidHandle) {
		return nil
	}
	defer procFindCloseStream.Call(handle)

	var results []Result
	for {
		name := syscall.UTF16ToString(data.StreamName[:])
		if name != "" && name != "::$DATA" {
			streamName := extractStreamName(name)
			if streamName != "" {
				fullPath := path + ":" + streamName
				contents := readADSContent(fullPath, data.StreamSize)
				results = append(results, Result{
					Path:     fullPath,
					Contents: contents,
					Type:     "ADS",
					Reason:   "NTFS alternate data stream",
				})
			}
		}

		var nextData win32FindStreamData
		ret, _, _ := procFindNextStreamW.Call(
			handle,
			uintptr(unsafe.Pointer(&nextData)),
		)
		if ret == 0 {
			break
		}
		data = nextData
	}

	return results
}

func extractStreamName(raw string) string {
	raw = strings.TrimPrefix(raw, ":")
	idx := strings.Index(raw, ":")
	if idx <= 0 {
		return ""
	}
	return raw[:idx]
}

func readADSContent(path string, size int64) string {
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
