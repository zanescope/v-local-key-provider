//go:build darwin && cgo

package provider

import darwinroute "github.com/zanescope/v-local-key-provider/internal/platform/darwin"

type darwinPBKDFCapture = darwinroute.PBKDFCapture

func darwinLLDBBreakpointCount(output string) int {
	return darwinroute.LLDBBreakpointCount(output)
}

func darwinHookPythonSource(architecture string) string {
	return darwinroute.HookPythonSource(architecture)
}

func darwinHookCommandFileWithPython(waitFor bool, executable, pythonPath string) string {
	return darwinroute.HookCommandFileWithPython(waitFor, executable, pythonPath, darwinWaitForProcessName(executable))
}

func parseDarwinHookPythonKeys(output string) [][]byte {
	return darwinroute.ParseHookPythonKeys(output)
}

func darwinHookPythonCount(output string) int {
	return darwinroute.HookPythonCount(output)
}

func parseDarwinPBKDFCaptures(output string) []darwinPBKDFCapture {
	return darwinroute.ParsePBKDFCaptures(output)
}

func darwinCapturedPIDs(output string) []int {
	return darwinroute.CapturedPIDs(output)
}

func darwinHookHasKeyOrPBKDFCapture(output string) bool {
	return darwinroute.HasKeyOrPBKDFCapture(output)
}
