//go:build !windows

package shadowsupervisor

import (
	"bufio"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	clockmodel "github.com/zanescope/v-local-key-provider/internal/shadowclock"
	shadowprocess "github.com/zanescope/v-local-key-provider/internal/shadowprocess"
	"golang.org/x/sys/unix"
)

type lineResult struct {
	frame Frame
	err   error
}

func readLine(reader *bufio.Reader) (Frame, error) {
	payload, err := reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return Frame{}, errors.New("supervisor line is oversized")
	}
	if err != nil && !(errors.Is(err, io.EOF) && len(payload) > 0) {
		return Frame{}, err
	}
	if len(payload) > maxFrameBytes {
		return Frame{}, errors.New("supervisor line is oversized")
	}
	return readFrame(bufio.NewReaderSize(bytesReader(payload), len(payload)))
}

type byteReader struct {
	payload []byte
}

func bytesReader(payload []byte) *byteReader { return &byteReader{payload: payload} }

func (value *byteReader) Read(target []byte) (int, error) {
	if len(value.payload) == 0 {
		return 0, io.EOF
	}
	read := copy(target, value.payload)
	value.payload = value.payload[read:]
	return read, nil
}

func sendFailure(control *os.File, code string) {
	_ = writeFrame(control, Frame{Version: ProtocolVersion, Type: "failed", ErrorCode: code})
}

func terminateOwned(command *exec.Cmd, finished <-chan error) error {
	if command == nil || command.Process == nil {
		return nil
	}
	pid := command.Process.Pid
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	select {
	case <-finished:
		return nil
	case <-time.After(300 * time.Millisecond):
	}
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	select {
	case <-finished:
		return nil
	case <-time.After(700 * time.Millisecond):
		return errors.New("owned process group did not stop")
	}
}

func accountEnvironment() ([]string, error) {
	uid := os.Geteuid()
	entry, err := user.LookupId(strconv.Itoa(uid))
	if err != nil || entry == nil || entry.HomeDir == "" || entry.Username == "" {
		return nil, errors.New("supervisor account environment is unavailable")
	}
	home := filepath.Clean(entry.HomeDir)
	resolved, err := filepath.EvalSymlinks(home)
	if err != nil || !filepath.IsAbs(home) || resolved != home {
		return nil, errors.New("supervisor account home is not canonical")
	}
	return []string{
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=" + home,
		"USER=" + entry.Username, "LOGNAME=" + entry.Username, "LANG=C", "LC_ALL=C",
	}, nil
}

// ExecGate is the pre-exec child entrypoint. The target executable cannot run
// before the supervisor publishes its PID/start binding and receives release.
func ExecGate(
	gateFD, statusFD int,
	supervisorDigest, executable, cloneRoot, executableDigest string,
	arguments []string,
) error {
	if gateFD < 3 || statusFD < 3 || gateFD == statusFD || !validDigest(supervisorDigest) || len(arguments) > 16 {
		return errors.New("pre-exec gate descriptors or arguments are invalid")
	}
	self, err := os.Executable()
	if err != nil {
		return errors.New("pre-exec supervisor executable is unavailable")
	}
	self, err = filepath.EvalSymlinks(filepath.Clean(self))
	if err != nil {
		return errors.New("pre-exec supervisor executable is not canonical")
	}
	selfDigest, err := digestFile(self)
	if err != nil || selfDigest != supervisorDigest {
		return errors.New("pre-exec supervisor build binding changed")
	}
	executable, _, err = canonicalExecutable(executable, cloneRoot)
	if err != nil {
		return err
	}
	currentDigest, err := digestFile(executable)
	if err != nil || currentDigest != executableDigest {
		return errors.New("pre-exec target digest changed")
	}
	environment, err := accountEnvironment()
	if err != nil {
		return err
	}
	gate := os.NewFile(uintptr(gateFD), "shadow-preexec-gate")
	status := os.NewFile(uintptr(statusFD), "shadow-preexec-status")
	if gate == nil || status == nil {
		return errors.New("pre-exec gate descriptors are unavailable")
	}
	defer gate.Close()
	defer status.Close()
	buffer := make([]byte, 1)
	if _, err := io.ReadFull(gate, buffer); err != nil || buffer[0] != 1 {
		return errors.New("pre-exec gate closed before release")
	}
	_ = gate.Close()
	executable, _, err = canonicalExecutable(executable, cloneRoot)
	if err != nil {
		return errors.New("pre-exec target binding changed while held")
	}
	currentDigest, err = digestFile(executable)
	if err != nil || currentDigest != executableDigest {
		return errors.New("pre-exec target digest changed while held")
	}
	unix.CloseOnExec(statusFD)
	argv := append([]string{executable}, arguments...)
	if err := syscall.Exec(executable, argv, environment); err != nil {
		_, _ = status.Write([]byte{1})
		return errors.New("pre-exec target could not start")
	}
	return nil
}

func waitForExec(status *os.File, timeout time.Duration) error {
	if status == nil {
		return nil
	}
	result := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1)
		read, err := status.Read(buffer)
		if errors.Is(err, io.EOF) && read == 0 {
			result <- nil
			return
		}
		result <- errors.New("pre-exec target reported a start failure")
	}()
	select {
	case err := <-result:
		return err
	case <-time.After(timeout):
		return errors.New("pre-exec target start acknowledgement timed out")
	}
}

func Serve(control *os.File, clock clockmodel.Clock) error {
	if control == nil || clock == nil {
		return errors.New("supervisor control or clock is missing")
	}
	unix.CloseOnExec(int(control.Fd()))
	defer control.Close()
	reader := bufio.NewReaderSize(control, maxFrameBytes+1)
	initChannel := make(chan lineResult, 1)
	go func() {
		frame, err := readLine(reader)
		initChannel <- lineResult{frame: frame, err: err}
	}()
	var init Frame
	select {
	case result := <-initChannel:
		if result.err != nil || result.frame.validateInit() != nil {
			sendFailure(control, "invalid_init")
			return errors.New("supervisor init was rejected")
		}
		init = result.frame
	case <-time.After(5 * time.Second):
		sendFailure(control, "init_timeout")
		return errors.New("supervisor init timed out")
	}
	remaining, err := clockmodel.Remaining(clock, init.LeaseDeadlineNS)
	if err != nil || remaining <= 0 {
		sendFailure(control, "lease_expired")
		return errors.New("supervisor lease expired before launch")
	}
	supervisorStartNS, err := shadowprocess.StartMonotonicNS(os.Getpid())
	if err != nil || supervisorStartNS == 0 {
		sendFailure(control, "supervisor_binding_failed")
		return errors.New("supervisor process start identity is unavailable")
	}
	self, err := os.Executable()
	if err != nil {
		sendFailure(control, "supervisor_binding_failed")
		return errors.New("supervisor executable is unavailable")
	}
	selfDigest, err := digestFile(self)
	if err != nil || selfDigest != init.SupervisorDigest {
		sendFailure(control, "supervisor_binding_failed")
		return errors.New("supervisor executable binding changed")
	}
	supervisor := Frame{
		Version: ProtocolVersion, Type: "supervisor_bound",
		SupervisorPID: os.Getpid(), SupervisorStartNS: supervisorStartNS,
		SupervisorDigest: init.SupervisorDigest,
	}
	if err := writeFrame(control, supervisor); err != nil {
		return errors.New("supervisor could not publish its process binding")
	}
	frames := make(chan lineResult)
	stopFrames := make(chan struct{})
	framesDone := make(chan struct{})
	go func() {
		defer close(framesDone)
		for {
			frame, err := readLine(reader)
			select {
			case frames <- lineResult{frame: frame, err: err}:
			case <-stopFrames:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	defer func() {
		close(stopFrames)
		_ = control.Close()
		select {
		case <-framesDone:
		case <-time.After(100 * time.Millisecond):
		}
	}()
	remaining, err = clockmodel.Remaining(clock, init.LeaseDeadlineNS)
	if err != nil || remaining <= 0 {
		sendFailure(control, "lease_expired")
		return errors.New("supervisor lease expired before prepare wait")
	}
	lease := time.NewTimer(remaining)
	defer lease.Stop()
	prepared := false
	for !prepared {
		select {
		case <-lease.C:
			sendFailure(control, "lease_expired")
			return nil
		case result := <-frames:
			if result.err != nil {
				return nil
			}
			if err := result.frame.validatePrepare(supervisor); err != nil {
				sendFailure(control, "binding_mismatch")
				continue
			}
			prepared = true
		}
	}
	remaining, err = clockmodel.Remaining(clock, init.LeaseDeadlineNS)
	if err != nil || remaining <= 0 {
		sendFailure(control, "lease_expired")
		return errors.New("supervisor lease expired before child preparation")
	}
	gateReader, gateWriter, err := os.Pipe()
	if err != nil {
		sendFailure(control, "gate_create_failed")
		return errors.New("supervisor gate creation failed")
	}
	defer gateReader.Close()
	defer gateWriter.Close()
	var command *exec.Cmd
	var statusReader *os.File
	var statusWriter *os.File
	if init.Mode == "synthetic" {
		command = exec.Command(init.Executable, init.Arguments...)
		command.Env = []string{"PATH=/usr/bin:/bin", "V_LOCAL_SHADOW_SYNTHETIC_GATE_FD=3"}
		command.ExtraFiles = []*os.File{gateReader}
	} else {
		statusReader, statusWriter, err = os.Pipe()
		if err != nil {
			sendFailure(control, "gate_create_failed")
			return errors.New("supervisor status gate creation failed")
		}
		defer statusReader.Close()
		defer statusWriter.Close()
		childArguments := []string{
			"exec-gate", "3", "4", init.SupervisorDigest, init.Executable, init.CloneRoot, init.ExecutableDigest,
		}
		childArguments = append(childArguments, init.Arguments...)
		command = exec.Command(self, childArguments...)
		command.Env = []string{"PATH=/usr/bin:/bin"}
		command.ExtraFiles = []*os.File{gateReader, statusWriter}
	}
	command.Dir = init.CloneRoot
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		sendFailure(control, "process_start_failed")
		return errors.New("supervisor could not start the owned process")
	}
	_ = gateReader.Close()
	if statusWriter != nil {
		_ = statusWriter.Close()
	}
	finished := make(chan error, 1)
	go func() { finished <- command.Wait() }()
	startNS, err := shadowprocess.StartMonotonicNS(command.Process.Pid)
	if err != nil {
		_ = terminateOwned(command, finished)
		return errors.New("owned process start identity is unavailable")
	}
	bound := Frame{
		Version: ProtocolVersion, Type: "bound", PID: command.Process.Pid, StartNS: startNS,
		SupervisorPID: os.Getpid(), SupervisorStartNS: supervisorStartNS,
		SupervisorDigest: init.SupervisorDigest,
		Executable:       init.Executable, CloneRoot: init.CloneRoot, ExecutableDigest: init.ExecutableDigest,
		LeaseDeadlineNS: init.LeaseDeadlineNS,
	}
	if err := writeFrame(control, bound); err != nil {
		_ = terminateOwned(command, finished)
		return errors.New("supervisor could not publish process binding")
	}
	released := false
	for {
		select {
		case <-lease.C:
			_ = terminateOwned(command, finished)
			sendFailure(control, "lease_expired")
			return nil
		case <-finished:
			_ = writeFrame(control, Frame{Version: ProtocolVersion, Type: "stopped", PID: bound.PID, StartNS: bound.StartNS})
			return nil
		case result := <-frames:
			if result.err != nil {
				_ = terminateOwned(command, finished)
				return nil
			}
			if err := result.frame.validateControl(bound); err != nil {
				sendFailure(control, "binding_mismatch")
				continue
			}
			switch result.frame.Type {
			case "release":
				if released {
					sendFailure(control, "release_repeated")
					continue
				}
				released = true
				if _, err := gateWriter.Write([]byte{1}); err != nil || gateWriter.Close() != nil {
					_ = terminateOwned(command, finished)
					return errors.New("supervisor could not release the owned gate")
				}
				if init.Mode == "preexec" {
					acknowledgementWindow := time.Second
					acknowledgementRemaining, remainingErr := clockmodel.Remaining(clock, init.LeaseDeadlineNS)
					if remainingErr != nil || acknowledgementRemaining <= 0 {
						_ = terminateOwned(command, finished)
						sendFailure(control, "lease_expired")
						return errors.New("supervisor lease expired before target acknowledgement")
					}
					if acknowledgementRemaining < acknowledgementWindow {
						acknowledgementWindow = acknowledgementRemaining
					}
					if acknowledgementWindow <= 0 || waitForExec(statusReader, acknowledgementWindow) != nil {
						_ = terminateOwned(command, finished)
						sendFailure(control, "process_start_failed")
						return errors.New("supervisor pre-exec target failed")
					}
				}
				_ = writeFrame(control, Frame{Version: ProtocolVersion, Type: "released", PID: bound.PID, StartNS: bound.StartNS})
			case "stop":
				if err := terminateOwned(command, finished); err != nil {
					sendFailure(control, "stop_failed")
					return err
				}
				_ = writeFrame(control, Frame{Version: ProtocolVersion, Type: "stopped", PID: bound.PID, StartNS: bound.StartNS})
				return nil
			}
		}
	}
}

func ServeFD(fd int) error {
	if fd < 3 {
		return errors.New("supervisor requires an inherited control descriptor")
	}
	control := os.NewFile(uintptr(fd), "shadow-supervisor-control-"+strconv.Itoa(fd))
	if control == nil {
		return errors.New("supervisor control descriptor is invalid")
	}
	return Serve(control, clockmodel.System{})
}
