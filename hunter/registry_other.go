//go:build !windows

package hunter

func scanRegistry() []Result {
	return nil
}
