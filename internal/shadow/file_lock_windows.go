//go:build windows

package shadow

import "errors"

type FileLocker struct{}

func NewFileLocker(string) (*FileLocker, error) {
	return nil, errors.New("macOS Shadow attempt lock is unavailable on Windows")
}
