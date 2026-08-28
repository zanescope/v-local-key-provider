//go:build windows

package windows

import (
	"path/filepath"
	"strings"
)

func NormalizeObservedPath(value string) string {
	value = strings.TrimSpace(value)
	lower := strings.ToLower(value)
	switch {
	case strings.HasPrefix(lower, `\\?\unc\`):
		value = `\\` + value[len(`\\?\UNC\`):]
	case strings.HasPrefix(lower, `\\?\`):
		value = value[len(`\\?\`):]
	}
	return filepath.Clean(value)
}

func PathWithin(child, parent string) bool {
	child = strings.ToLower(NormalizeObservedPath(child))
	parent = strings.ToLower(NormalizeObservedPath(parent))
	relative, err := filepath.Rel(parent, child)
	if err != nil || filepath.IsAbs(relative) {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func ObservedAccountRoot(path string) string {
	cursor := filepath.Dir(NormalizeObservedPath(path))
	for depth := 0; depth < 32; depth++ {
		if strings.EqualFold(filepath.Base(cursor), "db_storage") {
			return filepath.Dir(cursor)
		}
		parent := filepath.Dir(cursor)
		if parent == cursor {
			break
		}
		cursor = parent
	}
	return ""
}

func DatabaseHandleEvidence(path string) bool {
	name := strings.ToLower(filepath.Base(NormalizeObservedPath(path)))
	return strings.HasSuffix(name, ".db") || strings.HasSuffix(name, ".db-wal") ||
		strings.HasSuffix(name, ".db-shm") || strings.HasSuffix(name, ".db-journal")
}

func ClassifyObservedPaths(paths []string, accountDir, dbDir string) string {
	targetAccount := NormalizeObservedPath(accountDir)
	targetObserved := false
	otherObserved := false
	for _, path := range paths {
		if !DatabaseHandleEvidence(path) {
			continue
		}
		if PathWithin(path, dbDir) {
			targetObserved = true
		}
		root := ObservedAccountRoot(path)
		if root != "" && !strings.EqualFold(NormalizeObservedPath(root), targetAccount) {
			otherObserved = true
		}
	}
	if targetObserved && otherObserved {
		return "unknown"
	}
	if targetObserved {
		return "target"
	}
	if otherObserved {
		return "other"
	}
	return "unknown"
}
