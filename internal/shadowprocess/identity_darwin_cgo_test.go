//go:build darwin && cgo

package shadowprocess

import (
	"os"
	"os/exec"
	"testing"
)

func TestCurrentProcessStartIdentityIsStable(t *testing.T) {
	first, err := StartMonotonicNS(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	second, err := StartMonotonicNS(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if first == 0 || second != first {
		t.Fatalf("process start identity drifted: first=%d second=%d", first, second)
	}
}

func TestChildProcessStartIdentityCanBeReobserved(t *testing.T) {
	command := exec.Command("/bin/sleep", "5")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	}()
	first, err := StartMonotonicNS(command.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	second, err := StartMonotonicNS(command.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	self, err := StartMonotonicNS(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if first == 0 || second != first || first == self {
		t.Fatalf("child process start identity is not stable and distinct: first=%d second=%d self=%d", first, second, self)
	}
}
