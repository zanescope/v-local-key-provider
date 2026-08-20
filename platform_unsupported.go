//go:build !windows && !darwin

package main

import "errors"

func platformAcquire(targets databaseTargets, media mediaEvidence, options acquireOptions) (response, diagnostics, error) {
	return response{}, diagnostics{Platform: "unsupported"}, errors.New("当前平台尚未实现密钥获取")
}
