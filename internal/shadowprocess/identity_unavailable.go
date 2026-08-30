//go:build !darwin || !cgo

package shadowprocess

import "errors"

func systemStartMonotonicNS(int) (uint64, bool, error) {
	return 0, false, errors.New("OS process start identity is unavailable")
}
