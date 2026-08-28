//go:build !windows && !darwin

package provider

import "runtime"

func platformProcessInstanceID() string {
	return runtime.GOOS + ":unsupported"
}
