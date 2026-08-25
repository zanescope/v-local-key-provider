package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sync"
)

type executableDigestCacheEntry struct {
	size    int64
	mtimeNS int64
	digest  string
}

var executableDigestCache sync.Map

func executableSHA256(path string) string {
	if path == "" {
		return "unavailable"
	}
	info, err := os.Lstat(path)
	unsafePath := false
	if err == nil {
		unsafePath, err = pathIsLinkOrReparse(path, info.Mode())
	}
	if err != nil || unsafePath || !info.Mode().IsRegular() {
		return "unavailable"
	}
	file, err := os.Open(path)
	if err != nil {
		return "unavailable"
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return "unavailable"
	}
	identity, err := canonicalFileID(file)
	if err != nil {
		return "unavailable"
	}
	cacheKey := path + "\x00" + identity
	if cached, ok := executableDigestCache.Load(cacheKey); ok {
		entry := cached.(executableDigestCacheEntry)
		if entry.size == opened.Size() && entry.mtimeNS == opened.ModTime().UnixNano() {
			return entry.digest
		}
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "unavailable"
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || opened.ModTime() != after.ModTime() {
		return "unavailable"
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	executableDigestCache.Store(cacheKey, executableDigestCacheEntry{size: opened.Size(), mtimeNS: opened.ModTime().UnixNano(), digest: digest})
	return digest
}
