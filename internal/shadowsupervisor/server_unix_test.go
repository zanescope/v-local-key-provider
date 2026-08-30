//go:build !windows

package shadowsupervisor

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	clockmodel "github.com/zanescope/v-local-key-provider/internal/shadowclock"
	"golang.org/x/sys/unix"
)

func TestMain(main *testing.M) {
	if len(os.Args) == 3 && os.Args[1] == "serve-fd" {
		fd, err := strconv.Atoi(os.Args[2])
		if err != nil || ServeFD(fd) != nil {
			os.Exit(92)
		}
		os.Exit(0)
	}
	if len(os.Args) >= 8 && os.Args[1] == "exec-gate" {
		gateFD, gateErr := strconv.Atoi(os.Args[2])
		statusFD, statusErr := strconv.Atoi(os.Args[3])
		if gateErr != nil || statusErr != nil ||
			ExecGate(gateFD, statusFD, os.Args[4], os.Args[5], os.Args[6], os.Args[7], os.Args[8:]) != nil {
			os.Exit(91)
		}
		os.Exit(0)
	}
	os.Exit(main.Run())
}

func TestExecGateRejectsChangedSupervisorBuildBeforeTargetValidation(t *testing.T) {
	gateRead, gateWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer gateRead.Close()
	defer gateWrite.Close()
	statusRead, statusWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer statusRead.Close()
	defer statusWrite.Close()

	err = ExecGate(
		int(gateRead.Fd()),
		int(statusWrite.Fd()),
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"deliberately-not-a-target",
		"deliberately-not-a-clone-root",
		"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		nil,
	)
	if err == nil || err.Error() != "pre-exec supervisor build binding changed" {
		t.Fatalf("unexpected changed-build result: %v", err)
	}
}

func TestSupervisorSyntheticChild(t *testing.T) {
	if os.Getenv("V_LOCAL_SHADOW_SYNTHETIC_GATE_FD") != "3" {
		return
	}
	if err := os.WriteFile("started.marker", []byte("started"), 0o600); err != nil {
		os.Exit(20)
	}
	gate := os.NewFile(3, "synthetic-gate")
	if gate == nil {
		os.Exit(21)
	}
	buffer := make([]byte, 1)
	if _, err := io.ReadFull(gate, buffer); err != nil || buffer[0] != 1 {
		os.Exit(22)
	}
	_ = gate.Close()
	if err := os.WriteFile("released.marker", []byte("released"), 0o600); err != nil {
		os.Exit(23)
	}
	time.Sleep(30 * time.Second)
	os.Exit(0)
}

func TestSupervisorPreexecTarget(t *testing.T) {
	workingDirectory, err := os.Getwd()
	if err != nil || filepath.Base(workingDirectory) != "clone" {
		return
	}
	if err := os.WriteFile("preexec.marker", []byte("released"), 0o600); err != nil {
		os.Exit(31)
	}
	time.Sleep(30 * time.Second)
}

func canonicalSupervisorRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root = filepath.Join(root, "clone")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func copySupervisorHelper(t *testing.T, root string) string {
	t.Helper()
	sourcePath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target := filepath.Join(root, "synthetic-child")
	destination, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(destination, source); err != nil {
		_ = destination.Close()
		t.Fatal(err)
	}
	if err := destination.Close(); err != nil {
		t.Fatal(err)
	}
	return target
}

func socketPair(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_LOCAL, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	unix.CloseOnExec(fds[0])
	unix.CloseOnExec(fds[1])
	return os.NewFile(uintptr(fds[0]), "supervisor-server"), os.NewFile(uintptr(fds[1]), "supervisor-client")
}

func nextFrame(t *testing.T, client *os.File, reader *bufio.Reader) Frame {
	t.Helper()
	result := make(chan lineResult, 1)
	go func() {
		frame, err := readLine(reader)
		result <- lineResult{frame: frame, err: err}
	}()
	select {
	case value := <-result:
		if value.err != nil {
			t.Fatal(value.err)
		}
		return value.frame
	case <-time.After(3 * time.Second):
		_ = client.Close()
		t.Fatal("timed out waiting for supervisor frame")
	}
	return Frame{}
}

func waitProcessAbsent(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("owned process %d remains alive", pid)
}

func requireMarkerAbsent(t *testing.T, path string, duration time.Duration) {
	t.Helper()
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			t.Fatalf("marker appeared before the expected phase: %s", path)
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func requireClientControlClosed(t *testing.T, client *Client) {
	t.Helper()
	client.mu.Lock()
	defer client.mu.Unlock()
	if !client.closed || client.control != nil || client.reader != nil {
		t.Fatal("supervisor client retained its control descriptor")
	}
}

type sequenceClock struct {
	values []uint64
	index  int
}

func (value *sequenceClock) NowNS() (uint64, error) {
	if value.index >= len(value.values) {
		return 0, errors.New("sequence clock exhausted")
	}
	result := value.values[value.index]
	value.index++
	return result, nil
}

func supervisorInit(t *testing.T, clock clockmodel.Clock, root, executable string, lease time.Duration) Frame {
	t.Helper()
	now, err := clock.NowNS()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := digestFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	supervisorDigest, err := digestFile(self)
	if err != nil {
		t.Fatal(err)
	}
	return Frame{
		Version: ProtocolVersion, Type: "init", Mode: "synthetic", LeaseDeadlineNS: now + uint64(lease),
		Executable: executable, CloneRoot: root, ExecutableDigest: digest, SupervisorDigest: supervisorDigest,
		Arguments: []string{"-test.run=^TestSupervisorSyntheticChild$"},
	}
}

func expectSupervisorBinding(t *testing.T, client *os.File, reader *bufio.Reader) Frame {
	t.Helper()
	supervisor := nextFrame(t, client, reader)
	if supervisor.Type != "supervisor_bound" || supervisor.PID != 0 || supervisor.StartNS != 0 ||
		supervisor.SupervisorPID != os.Getpid() || supervisor.SupervisorStartNS == 0 ||
		!validDigest(supervisor.SupervisorDigest) {
		t.Fatalf("invalid supervisor self binding: %+v", supervisor)
	}
	return supervisor
}

func prepareTarget(t *testing.T, client *os.File, reader *bufio.Reader, supervisor Frame) Frame {
	t.Helper()
	if err := writeFrame(client, Frame{
		Version: ProtocolVersion, Type: "prepare", SupervisorPID: supervisor.SupervisorPID,
		SupervisorStartNS: supervisor.SupervisorStartNS, SupervisorDigest: supervisor.SupervisorDigest,
	}); err != nil {
		t.Fatal(err)
	}
	return nextFrame(t, client, reader)
}

func TestInheritedDescriptorSupervisorBindsBeforeReleaseAndCleansOnEOF(t *testing.T) {
	root := canonicalSupervisorRoot(t)
	executable := copySupervisorHelper(t, root)
	server, client := socketPair(t)
	clock := clockmodel.System{}
	finished := make(chan error, 1)
	go func() { finished <- Serve(server, clock) }()
	if err := writeFrame(client, supervisorInit(t, clock, root, executable, 5*time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReaderSize(client, maxFrameBytes+1)
	supervisor := expectSupervisorBinding(t, client, reader)
	requireMarkerAbsent(t, filepath.Join(root, "started.marker"), 100*time.Millisecond)
	if err := writeFrame(client, Frame{
		Version: ProtocolVersion, Type: "prepare", SupervisorPID: supervisor.SupervisorPID + 1,
		SupervisorStartNS: supervisor.SupervisorStartNS, SupervisorDigest: supervisor.SupervisorDigest,
	}); err != nil {
		t.Fatal(err)
	}
	rejectedPrepare := nextFrame(t, client, reader)
	if rejectedPrepare.Type != "failed" || rejectedPrepare.ErrorCode != "binding_mismatch" {
		t.Fatalf("wrong supervisor binding was not rejected: %+v", rejectedPrepare)
	}
	requireMarkerAbsent(t, filepath.Join(root, "started.marker"), 50*time.Millisecond)
	bound := prepareTarget(t, client, reader, supervisor)
	if bound.Type != "bound" || bound.PID <= 0 || bound.StartNS == 0 || bound.SupervisorPID != os.Getpid() ||
		bound.SupervisorStartNS != supervisor.SupervisorStartNS || bound.SupervisorDigest != supervisor.SupervisorDigest ||
		bound.SupervisorPID == bound.PID {
		t.Fatalf("invalid supervisor binding: %+v", bound)
	}
	if _, err := os.Stat(filepath.Join(root, "released.marker")); !os.IsNotExist(err) {
		t.Fatal("synthetic child executed before Provider persisted the binding")
	}
	wrong := Frame{Version: ProtocolVersion, Type: "stop", PID: bound.PID + 1, StartNS: bound.StartNS}
	if err := writeFrame(client, wrong); err != nil {
		t.Fatal(err)
	}
	rejected := nextFrame(t, client, reader)
	if rejected.Type != "failed" || rejected.ErrorCode != "binding_mismatch" {
		t.Fatalf("wrong PID/start binding was not rejected: %+v", rejected)
	}
	if err := writeFrame(client, Frame{Version: ProtocolVersion, Type: "release", PID: bound.PID, StartNS: bound.StartNS}); err != nil {
		t.Fatal(err)
	}
	if released := nextFrame(t, client, reader); released.Type != "released" {
		t.Fatalf("release was not acknowledged: %+v", released)
	}
	// Package-level test runs can briefly delay exec under load even after the
	// supervisor has released the inherited gate. Keep this proof below the
	// synthetic ten-second target without making a two-second scheduler delay
	// look like a supervisor failure.
	markerDeadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(root, "released.marker")); err == nil {
			break
		}
		if time.Now().After(markerDeadline) {
			t.Fatal("released synthetic child did not execute")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("supervisor did not react to Provider EOF")
	}
	waitProcessAbsent(t, bound.PID)
}

func TestSupervisorClientBindsReleasesAndCleansOnProviderEOF(t *testing.T) {
	root := canonicalSupervisorRoot(t)
	executable := copySupervisorHelper(t, root)
	digest, err := digestFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, supervisor, err := Start(ctx, StartConfig{
		SupervisorPath: executable, SupervisorDigest: digest,
		Init: supervisorInit(t, clockmodel.System{}, root, executable, 5*time.Second), ResponseTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cleanupCancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, _ = client.CloseProvider(cleanup)
		cleanupCancel()
	})
	currentSupervisor := client.SupervisorBound()
	if supervisor.Type != "supervisor_bound" || supervisor.SupervisorPID <= 0 ||
		currentSupervisor.SupervisorPID != supervisor.SupervisorPID ||
		currentSupervisor.SupervisorStartNS != supervisor.SupervisorStartNS ||
		currentSupervisor.SupervisorDigest != supervisor.SupervisorDigest {
		t.Fatalf("client returned an invalid supervisor binding: %+v", supervisor)
	}
	if current := client.Bound(); current.PID != 0 || current.StartNS != 0 {
		t.Fatalf("client bound a child before prepare: %+v", current)
	}
	requireMarkerAbsent(t, filepath.Join(root, "started.marker"), 100*time.Millisecond)
	bound, err := client.Prepare(ctx)
	if err != nil {
		t.Fatal(err)
	}
	current := client.Bound()
	if bound.Type != "bound" || bound.PID <= 0 || current.PID != bound.PID || current.StartNS != bound.StartNS ||
		current.SupervisorPID != bound.SupervisorPID || current.SupervisorStartNS != bound.SupervisorStartNS ||
		current.Executable != bound.Executable || current.CloneRoot != bound.CloneRoot ||
		current.ExecutableDigest != bound.ExecutableDigest || current.LeaseDeadlineNS != bound.LeaseDeadlineNS {
		t.Fatalf("client returned an invalid binding: %+v", bound)
	}
	if _, err := os.Stat(filepath.Join(root, "released.marker")); !os.IsNotExist(err) {
		t.Fatal("client target executed before release")
	}
	if err := client.Release(ctx); err != nil {
		t.Fatal(err)
	}
	markerDeadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(root, "released.marker")); err == nil {
			break
		}
		if time.Now().After(markerDeadline) {
			t.Fatal("client release did not reach the synthetic target")
		}
		time.Sleep(10 * time.Millisecond)
	}
	supervisorPID := client.command.Process.Pid
	if clean, err := client.CloseProvider(ctx); err != nil || !clean {
		t.Fatalf("Provider EOF cleanup failed: clean=%v err=%v", clean, err)
	}
	requireClientControlClosed(t, client)
	waitProcessAbsent(t, bound.PID)
	waitProcessAbsent(t, supervisorPID)
}

func TestSupervisorClientStopCleansBeforeRelease(t *testing.T) {
	root := canonicalSupervisorRoot(t)
	executable := copySupervisorHelper(t, root)
	digest, err := digestFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, supervisor, err := Start(ctx, StartConfig{
		SupervisorPath: executable, SupervisorDigest: digest,
		Init: supervisorInit(t, clockmodel.System{}, root, executable, 5*time.Second), ResponseTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if supervisor.Type != "supervisor_bound" || supervisor.SupervisorPID != client.command.Process.Pid {
		t.Fatalf("client returned an invalid supervisor binding: %+v", supervisor)
	}
	requireMarkerAbsent(t, filepath.Join(root, "started.marker"), 100*time.Millisecond)
	bound, err := client.Prepare(ctx)
	if err != nil {
		t.Fatal(err)
	}
	supervisorPID := client.command.Process.Pid
	if clean, err := client.Stop(ctx); err != nil || !clean {
		t.Fatalf("client stop failed: clean=%v err=%v", clean, err)
	}
	requireClientControlClosed(t, client)
	waitProcessAbsent(t, bound.PID)
	waitProcessAbsent(t, supervisorPID)
	if _, err := os.Stat(filepath.Join(root, "released.marker")); !os.IsNotExist(err) {
		t.Fatal("stopped target crossed the release gate")
	}
}

func TestSupervisorLeaseStopsUnreleasedSyntheticProcess(t *testing.T) {
	root := canonicalSupervisorRoot(t)
	executable := copySupervisorHelper(t, root)
	server, client := socketPair(t)
	defer client.Close()
	clock := clockmodel.System{}
	finished := make(chan error, 1)
	go func() { finished <- Serve(server, clock) }()
	if err := writeFrame(client, supervisorInit(t, clock, root, executable, 1500*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReaderSize(client, maxFrameBytes+1)
	supervisor := expectSupervisorBinding(t, client, reader)
	requireMarkerAbsent(t, filepath.Join(root, "started.marker"), 100*time.Millisecond)
	bound := prepareTarget(t, client, reader, supervisor)
	if bound.Type != "bound" {
		t.Fatalf("invalid binding: %+v", bound)
	}
	expired := nextFrame(t, client, reader)
	if expired.Type != "failed" || expired.ErrorCode != "lease_expired" {
		t.Fatalf("lease expiry was not reported: %+v", expired)
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("lease expiry did not stop supervisor")
	}
	waitProcessAbsent(t, bound.PID)
	if _, err := os.Stat(filepath.Join(root, "released.marker")); !os.IsNotExist(err) {
		t.Fatal("lease-expired process crossed the release gate")
	}
}

func TestPreexecSupervisorDoesNotRunTargetBeforeBoundRelease(t *testing.T) {
	root := canonicalSupervisorRoot(t)
	executable := copySupervisorHelper(t, root)
	server, client := socketPair(t)
	clock := clockmodel.System{}
	finished := make(chan error, 1)
	go func() { finished <- Serve(server, clock) }()
	init := supervisorInit(t, clock, root, executable, 5*time.Second)
	init.Mode = "preexec"
	init.Arguments = []string{"-test.run=^TestSupervisorPreexecTarget$"}
	if err := writeFrame(client, init); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReaderSize(client, maxFrameBytes+1)
	supervisor := expectSupervisorBinding(t, client, reader)
	requireMarkerAbsent(t, filepath.Join(root, "preexec.marker"), 100*time.Millisecond)
	bound := prepareTarget(t, client, reader, supervisor)
	if bound.Type != "bound" || bound.PID <= 0 || bound.Executable != executable {
		t.Fatalf("invalid pre-exec binding: %+v", bound)
	}
	if _, err := os.Stat(filepath.Join(root, "preexec.marker")); !os.IsNotExist(err) {
		t.Fatal("pre-exec target ran before binding release")
	}
	if err := writeFrame(client, Frame{Version: ProtocolVersion, Type: "release", PID: bound.PID, StartNS: bound.StartNS}); err != nil {
		t.Fatal(err)
	}
	if released := nextFrame(t, client, reader); released.Type != "released" {
		t.Fatalf("pre-exec release was not acknowledged: %+v", released)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(root, "preexec.marker")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("released pre-exec target did not run")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("pre-exec supervisor did not react to Provider EOF")
	}
	waitProcessAbsent(t, bound.PID)
}

func TestSupervisorLeaseExpiresBeforePrepareWithoutStartingProcess(t *testing.T) {
	root := canonicalSupervisorRoot(t)
	executable := copySupervisorHelper(t, root)
	server, client := socketPair(t)
	defer client.Close()
	clock := clockmodel.System{}
	finished := make(chan error, 1)
	go func() { finished <- Serve(server, clock) }()
	if err := writeFrame(client, supervisorInit(t, clock, root, executable, 300*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReaderSize(client, maxFrameBytes+1)
	_ = expectSupervisorBinding(t, client, reader)
	requireMarkerAbsent(t, filepath.Join(root, "started.marker"), 100*time.Millisecond)
	expired := nextFrame(t, client, reader)
	if expired.Type != "failed" || expired.ErrorCode != "lease_expired" {
		t.Fatalf("pre-prepare lease expiry was not reported: %+v", expired)
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pre-prepare lease expiry did not stop supervisor")
	}
	requireMarkerAbsent(t, filepath.Join(root, "started.marker"), 50*time.Millisecond)
}

func TestSupervisorClientProviderEOFBeforePrepareStartsNoChild(t *testing.T) {
	root := canonicalSupervisorRoot(t)
	executable := copySupervisorHelper(t, root)
	digest, err := digestFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, supervisor, err := Start(ctx, StartConfig{
		SupervisorPath: executable, SupervisorDigest: digest,
		Init: supervisorInit(t, clockmodel.System{}, root, executable, 5*time.Second), ResponseTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if supervisor.Type != "supervisor_bound" || supervisor.SupervisorPID != client.command.Process.Pid {
		t.Fatalf("client returned an invalid supervisor binding: %+v", supervisor)
	}
	requireMarkerAbsent(t, filepath.Join(root, "started.marker"), 100*time.Millisecond)
	if clean, err := client.CloseProvider(ctx); err != nil || !clean {
		t.Fatalf("pre-prepare Provider EOF cleanup failed: clean=%v err=%v", clean, err)
	}
	requireClientControlClosed(t, client)
	waitProcessAbsent(t, supervisor.SupervisorPID)
	requireMarkerAbsent(t, filepath.Join(root, "started.marker"), 50*time.Millisecond)
}

func TestSupervisorRechecksAbsoluteLeaseBeforeWaitingForPrepare(t *testing.T) {
	root := canonicalSupervisorRoot(t)
	executable := copySupervisorHelper(t, root)
	server, client := socketPair(t)
	defer client.Close()
	init := supervisorInit(t, clockmodel.System{}, root, executable, time.Second)
	init.LeaseDeadlineNS = 200
	clock := &sequenceClock{values: []uint64{100, 250}}
	finished := make(chan error, 1)
	go func() { finished <- Serve(server, clock) }()
	if err := writeFrame(client, init); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReaderSize(client, maxFrameBytes+1)
	_ = expectSupervisorBinding(t, client, reader)
	expired := nextFrame(t, client, reader)
	if expired.Type != "failed" || expired.ErrorCode != "lease_expired" {
		t.Fatalf("absolute lease drift was not rejected: %+v", expired)
	}
	if err := <-finished; err == nil {
		t.Fatal("expired absolute lease returned success")
	}
	requireMarkerAbsent(t, filepath.Join(root, "started.marker"), 50*time.Millisecond)
}

func TestSupervisorResponseValidatorsRejectExtraOrMismatchedFields(t *testing.T) {
	digest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	supervisor := Frame{
		Version: ProtocolVersion, Type: "supervisor_bound", SupervisorPID: 101,
		SupervisorStartNS: 102, SupervisorDigest: digest,
	}
	if err := supervisor.validateSupervisorBound(101, digest); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Frame){
		"version":          func(value *Frame) { value.Version++ },
		"pid":              func(value *Frame) { value.SupervisorPID++ },
		"child pid":        func(value *Frame) { value.PID = 1 },
		"unexpected path":  func(value *Frame) { value.Executable = "/tmp/forged" },
		"unexpected error": func(value *Frame) { value.ErrorCode = "forged" },
	} {
		t.Run("supervisor_"+name, func(t *testing.T) {
			candidate := supervisor
			mutate(&candidate)
			if candidate.validateSupervisorBound(101, digest) == nil {
				t.Fatalf("invalid supervisor response was accepted: %+v", candidate)
			}
		})
	}

	init := Frame{
		LeaseDeadlineNS: 1000, Executable: "/tmp/clone/child", CloneRoot: "/tmp/clone",
		ExecutableDigest: digest,
	}
	bound := Frame{
		Version: ProtocolVersion, Type: "bound", LeaseDeadlineNS: init.LeaseDeadlineNS,
		Executable: init.Executable, CloneRoot: init.CloneRoot, ExecutableDigest: init.ExecutableDigest,
		PID: 201, StartNS: 202, SupervisorPID: supervisor.SupervisorPID,
		SupervisorStartNS: supervisor.SupervisorStartNS, SupervisorDigest: supervisor.SupervisorDigest,
	}
	if err := bound.validateBound(init, supervisor); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Frame){
		"version": func(value *Frame) { value.Version++ },
		"lease":   func(value *Frame) { value.LeaseDeadlineNS++ },
		"supervisor digest": func(value *Frame) {
			value.SupervisorDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		},
		"arguments": func(value *Frame) { value.Arguments = []string{"forged"} },
		"error":     func(value *Frame) { value.ErrorCode = "forged" },
	} {
		t.Run("bound_"+name, func(t *testing.T) {
			candidate := bound
			mutate(&candidate)
			if candidate.validateBound(init, supervisor) == nil {
				t.Fatalf("invalid child binding was accepted: %+v", candidate)
			}
		})
	}

	ack := Frame{Version: ProtocolVersion, Type: "released", PID: bound.PID, StartNS: bound.StartNS}
	if err := ack.validateAcknowledgement("released", bound); err != nil {
		t.Fatal(err)
	}
	ack.SupervisorPID = supervisor.SupervisorPID
	if ack.validateAcknowledgement("released", bound) == nil {
		t.Fatalf("acknowledgement with extra binding was accepted: %+v", ack)
	}
}

func TestSupervisorRejectsProductionModeBeforeStartingAProcess(t *testing.T) {
	root := canonicalSupervisorRoot(t)
	executable := copySupervisorHelper(t, root)
	server, client := socketPair(t)
	defer client.Close()
	finished := make(chan error, 1)
	go func() { finished <- Serve(server, clockmodel.System{}) }()
	init := supervisorInit(t, clockmodel.System{}, root, executable, time.Second)
	init.Mode = "production"
	if err := writeFrame(client, init); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReaderSize(client, maxFrameBytes+1)
	failed := nextFrame(t, client, reader)
	if failed.Type != "failed" || failed.ErrorCode != "invalid_init" {
		t.Fatalf("production supervisor route was not disabled: %+v", failed)
	}
	if err := <-finished; err == nil {
		t.Fatal("invalid production init returned success")
	}
}
