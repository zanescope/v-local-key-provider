//go:build darwin && cgo

package shadowproduction

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	shadowmodel "github.com/zanescope/v-local-key-provider/internal/shadow"
	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
	shadowprocess "github.com/zanescope/v-local-key-provider/internal/shadowprocess"
)

func startBoundProcess(t *testing.T) *exec.Cmd {
	t.Helper()
	command := exec.Command("/bin/sleep", "5")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if command.ProcessState == nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	return command
}

func stopBoundProcess(t *testing.T, command *exec.Cmd) {
	t.Helper()
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("killed synthetic process unexpectedly returned success")
	}
}

func TestSystemProcessesProvesOnlyExactJournaledBirthIdentities(t *testing.T) {
	_, record := adapterRecordFixture(t)
	supervisor := startBoundProcess(t)
	child := startBoundProcess(t)
	supervisorStart, err := shadowprocess.StartMonotonicNS(supervisor.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	childStart, err := shadowprocess.StartMonotonicNS(child.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	supervisorDigest := ""
	for _, resource := range record.Resources {
		if resource.Kind == "supervisor" {
			supervisorDigest = resource.DigestSHA256
		}
	}
	record.Supervisor = &shadowmodel.SupervisorProcessBinding{
		PID: supervisor.Process.Pid, StartMonotonicNS: supervisorStart, Digest: supervisorDigest,
	}
	record.SupervisorLeaseNS = record.Deadline.CaptureStopNS
	record.Process = &contract.ProcessBinding{
		PID: child.Process.Pid, StartMonotonicNS: childStart,
		SupervisorPID: supervisor.Process.Pid, SupervisorStartMonotonicNS: supervisorStart,
		ExecutableLeaf:   record.RootLeaf + "/WeChat.app/Contents/MacOS/SyntheticTarget",
		ExecutableDigest: strings.Repeat("d", 64), CloneRootLeaf: record.RootLeaf,
		SupervisorDigest: supervisorDigest,
	}
	record.PendingAction = shadowmodel.ActionReleaseLaunch
	if err := record.Validate(); err != nil {
		t.Fatal(err)
	}
	processes := SystemProcesses{}
	facts, err := processes.Absent(context.Background(), record)
	if err != nil || facts.ProcessAbsent || facts.SupervisorAbsent {
		t.Fatalf("live exact processes were reported absent: facts=%+v err=%v", facts, err)
	}
	stopBoundProcess(t, child)
	facts, err = processes.Absent(context.Background(), record)
	if err != nil || !facts.ProcessAbsent || facts.SupervisorAbsent {
		t.Fatalf("child-only cleanup was not observed exactly: facts=%+v err=%v", facts, err)
	}
	stopBoundProcess(t, supervisor)
	facts, err = processes.Absent(context.Background(), record)
	if err != nil || !facts.ProcessAbsent || !facts.SupervisorAbsent {
		t.Fatalf("complete exact cleanup was not observed: facts=%+v err=%v", facts, err)
	}
}
