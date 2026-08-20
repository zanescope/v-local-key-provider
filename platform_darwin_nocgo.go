//go:build darwin && !cgo

package main

import "errors"

func platformAcquire(targets databaseTargets, media mediaEvidence, options acquireOptions) (response, diagnostics, error) {
	return response{}, diagnostics{
		Platform: "darwin", ProcessAccessStatus: "unavailable",
		ProcessAccessError: "cgo_required", HelperStatus: options.helperStatus,
	}, errors.New("macOS 密钥获取需要启用 cgo 以调用 Mach 只读内存 API")
}
