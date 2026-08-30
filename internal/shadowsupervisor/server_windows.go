//go:build windows

package shadowsupervisor

import "errors"

func ServeFD(int) error {
	return errors.New("macOS Shadow supervisor is unavailable on Windows")
}
