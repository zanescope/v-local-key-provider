package provider

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func sameCanonicalPath(left, right string) bool {
	leftResolved, leftErr := filepath.EvalSymlinks(left)
	rightResolved, rightErr := filepath.EvalSymlinks(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	leftAbs, leftErr := filepath.Abs(leftResolved)
	rightAbs, rightErr := filepath.Abs(rightResolved)
	if leftErr != nil || rightErr != nil {
		return false
	}
	leftInfo, leftStatErr := os.Stat(leftAbs)
	rightInfo, rightStatErr := os.Stat(rightAbs)
	if leftStatErr == nil && rightStatErr == nil {
		return os.SameFile(leftInfo, rightInfo)
	}
	leftClean := filepath.Clean(leftAbs)
	rightClean := filepath.Clean(rightAbs)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(leftClean, rightClean)
	}
	return leftClean == rightClean
}
