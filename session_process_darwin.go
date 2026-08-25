//go:build darwin && cgo

package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

func platformProcessInstanceID() string {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	processes, _, err := darwinTargetProcesses()
	if err != nil {
		return "darwin:process-list-unavailable"
	}
	identities := make([]string, 0, len(processes))
	for _, process := range processes {
		started, _ := runBoundedDarwinOutput(
			ctx, "/bin/ps", []string{"-p", strconv.Itoa(process.pid), "-o", "lstart="}, 4*1024,
		)
		executable := darwinProcessExecutable(process)
		identities = append(identities, fmt.Sprintf("%d:%s:%s:%s:%s:%s",
			process.pid, strings.TrimSpace(string(started)), executable,
			darwinProcessArchitecture(process), darwinProcessVersion(process), executableSHA256(executable)))
		zeroBytes(started)
	}
	sort.Strings(identities)
	sum := sha256.Sum256([]byte(strings.Join(identities, "\x00")))
	return "darwin:" + hex.EncodeToString(sum[:16])
}
