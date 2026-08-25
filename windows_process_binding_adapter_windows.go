//go:build windows

package provider

import windowsroute "github.com/zanescope/v-local-key-provider/internal/platform/windows"

func normalizeWindowsObservedPath(value string) string {
	return windowsroute.NormalizeObservedPath(value)
}

func windowsPathWithin(child, parent string) bool {
	return windowsroute.PathWithin(child, parent)
}

func windowsObservedAccountRoot(path string) string {
	return windowsroute.ObservedAccountRoot(path)
}

func windowsDatabaseHandleEvidence(path string) bool {
	return windowsroute.DatabaseHandleEvidence(path)
}

func classifyWindowsObservedPaths(paths []string, accountDir, dbDir string) string {
	return windowsroute.ClassifyObservedPaths(paths, accountDir, dbDir)
}
