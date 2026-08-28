//go:build darwin && !cgo

package provider

import "errors"

func platformAcquire(targets databaseTargets, media mediaEvidence, options acquireOptions) (response, diagnostics, error) {
	diag := newDiagnostics("darwin", requestedScopes(options.Database, options.Media))
	diag.ProcessAccessStatus = "unavailable"
	diag.ProcessAccessError = "cgo_required"
	diag.HelperStatus = options.HelperStatus
	return response{}, diag, errors.New("macOS 密钥获取需要启用 cgo 以调用 Mach 只读内存 API")
}
