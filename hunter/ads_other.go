//go:build !windows

package hunter

func scanADS(_ string) []Result {
	return nil
}
