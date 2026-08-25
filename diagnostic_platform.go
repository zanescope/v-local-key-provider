package provider

import "runtime"

func platformNameForDiagnostics() string {
	if runtime.GOOS == "darwin" {
		return "darwin"
	}
	return runtime.GOOS
}
