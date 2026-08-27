package provider

import "runtime/debug"

func hardenSensitiveProcess() error {
	// 协议错误会被主动脱敏；panic 不得以包含请求 buffer 的完整 goroutine dump 绕过
	// 该策略。
	debug.SetTraceback("none")
	return hardenPlatformCrashReporting()
}
