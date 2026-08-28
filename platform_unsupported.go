//go:build !windows && !darwin

package provider

import "errors"

func platformAcquire(targets databaseTargets, media mediaEvidence, options acquireOptions) (response, diagnostics, error) {
	diag := newDiagnostics("unsupported", requestedScopes(options.Database, options.Media))
	return response{}, diag, errors.New("当前平台尚未实现密钥获取")
}
