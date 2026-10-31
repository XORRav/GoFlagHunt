package hunter

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxArchiveSize   = 50 * 1024 * 1024
	maxFileInArchive = 1024 * 1024
	maxArchiveFiles  = 100
)

func isArchive(ext string) bool {
	switch ext {
	case ".zip", ".tar", ".tgz":
		return true
	case ".gz":
		return true
	}
	return false
}

func isDatabase(ext string) bool {
	return ext == ".sqlite" || ext == ".db" || ext == ".sqlite3"
}

func scanArchive(path string, size int64) []Result {
	if size > maxArchiveSize || size == 0 {
		return nil
	}
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".zip":
		return scanZip(path)
	case ".tgz":
		return scanTarGz(path)
	case ".gz":
		if strings.HasSuffix(strings.ToLower(path), ".tar.gz") {
			return scanTarGz(path)
		}
	case ".tar":
		return scanTar(path)
	}
	return nil
}

func scanZip(path string) []Result {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil
	}
	defer r.Close()

	var results []Result
	count := 0

	for _, f := range r.File {
		if count >= maxArchiveFiles {
			break
		}
		if f.FileInfo().IsDir() {
			continue
		}
		count++

		name := filepath.Base(f.Name)

		for _, flagName := range DefaultFlagNames {
			if strings.EqualFold(name, flagName) {
				contents := readZipEntry(f)
				results = append(results, Result{
					Path:       path + " -> " + f.Name,
					Contents:   contents,
					Type:       "ARCHIVE",
					Reason:     "flag file inside zip",
					Confidence: 70,
				})
				break
			}
		}

		if f.UncompressedSize64 > 0 && f.UncompressedSize64 <= uint64(maxPatternSize) {
			data := readZipEntryRaw(f)
			if data != nil {
				for i, re := range compiledCTF {
					if re.Match(data) {
						results = append(results, Result{
							Path:       path + " -> " + f.Name,
							Contents:   truncate(string(data), 512),
							Type:       "ARCHIVE",
							Reason:     "pattern in zip: " + DefaultCTFPatterns[i],
							Confidence: 70,
						})
						break
					}
				}
			}
		}
	}
	return results
}

func scanTarGz(path string) []Result {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil
	}
	defer gz.Close()

	return scanTarReader(path, tar.NewReader(gz))
}

func scanTar(path string) []Result {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	return scanTarReader(path, tar.NewReader(f))
}

func scanTarReader(archivePath string, tr *tar.Reader) []Result {
	var results []Result
	count := 0

	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if count >= maxArchiveFiles {
			break
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		count++

		name := filepath.Base(hdr.Name)

		for _, flagName := range DefaultFlagNames {
			if strings.EqualFold(name, flagName) {
				data := readTarEntry(tr, hdr.Size)
				results = append(results, Result{
					Path:       archivePath + " -> " + hdr.Name,
					Contents:   truncate(string(data), 512),
					Type:       "ARCHIVE",
					Reason:     "flag file inside tar",
					Confidence: 70,
				})
				break
			}
		}

		if hdr.Size > 0 && hdr.Size <= maxPatternSize {
			data := readTarEntry(tr, hdr.Size)
			if data != nil {
				for i, re := range compiledCTF {
					if re.Match(data) {
						results = append(results, Result{
							Path:       archivePath + " -> " + hdr.Name,
							Contents:   truncate(string(data), 512),
							Type:       "ARCHIVE",
							Reason:     "pattern in tar: " + DefaultCTFPatterns[i],
							Confidence: 70,
						})
						break
					}
				}
			}
		}
	}
	return results
}

func scanDatabase(path string, size int64) []Result {
	if size > maxArchiveSize || size == 0 {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var results []Result
	for i, re := range compiledCTF {
		loc := re.FindIndex(data)
		if loc != nil {
			start := loc[0] - 30
			if start < 0 {
				start = 0
			}
			end := loc[1] + 30
			if end > len(data) {
				end = len(data)
			}
			context := extractPrintable(data[start:end])
			results = append(results, Result{
				Path:       path,
				Contents:   context,
				Type:       "PATTERN",
				Reason:     "CTF pattern in database: " + DefaultCTFPatterns[i],
				Confidence: 70,
			})
			break
		}
	}
	return results
}

func readZipEntry(f *zip.File) string {
	if f.UncompressedSize64 > uint64(maxFileInArchive) {
		return ""
	}
	rc, err := f.Open()
	if err != nil {
		return ""
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, maxFileInArchive))
	if err != nil {
		return ""
	}
	return truncate(string(data), 512)
}

func readZipEntryRaw(f *zip.File) []byte {
	if f.UncompressedSize64 > uint64(maxFileInArchive) {
		return nil
	}
	rc, err := f.Open()
	if err != nil {
		return nil
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, maxFileInArchive))
	if err != nil {
		return nil
	}
	for _, b := range data {
		if b == 0 {
			return nil
		}
	}
	return data
}

func readTarEntry(tr *tar.Reader, size int64) []byte {
	if size > maxFileInArchive {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(tr, maxFileInArchive))
	if err != nil {
		return nil
	}
	return data
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func extractPrintable(data []byte) string {
	var sb strings.Builder
	for _, b := range data {
		if b >= 32 && b < 127 {
			sb.WriteByte(b)
		} else if b == '\n' || b == '\r' || b == '\t' {
			sb.WriteByte(' ')
		}
	}
	s := sb.String()
	return truncate(strings.TrimSpace(s), 512)
}
