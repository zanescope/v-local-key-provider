package shadowsupervisor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	ProtocolVersion = 1
	maxFrameBytes   = 32 * 1024
)

type Frame struct {
	Version           int      `json:"version"`
	Type              string   `json:"type"`
	Mode              string   `json:"mode,omitempty"`
	LeaseDeadlineNS   uint64   `json:"lease_deadline_ns,omitempty"`
	Executable        string   `json:"executable,omitempty"`
	CloneRoot         string   `json:"clone_root,omitempty"`
	ExecutableDigest  string   `json:"executable_digest,omitempty"`
	Arguments         []string `json:"arguments,omitempty"`
	PID               int      `json:"pid,omitempty"`
	StartNS           uint64   `json:"start_ns,omitempty"`
	SupervisorPID     int      `json:"supervisor_pid,omitempty"`
	SupervisorStartNS uint64   `json:"supervisor_start_ns,omitempty"`
	SupervisorDigest  string   `json:"supervisor_digest,omitempty"`
	ErrorCode         string   `json:"error_code,omitempty"`
}

func validDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func digestFile(path string) (string, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		before.Size() <= 0 || before.Size() > 256*1024*1024 {
		return "", errors.New("supervised executable is not an exact regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return "", errors.New("supervised executable drifted before read")
	}
	digest := sha256.New()
	read, err := io.Copy(digest, io.LimitReader(file, 256*1024*1024+1))
	if err != nil || read != before.Size() || read > 256*1024*1024 {
		return "", errors.New("supervised executable is oversized or unreadable")
	}
	after, statErr := file.Stat()
	pathAfter, pathErr := os.Lstat(path)
	resolvedAfter, resolveErr := filepath.EvalSymlinks(path)
	if statErr != nil || pathErr != nil || resolveErr != nil || resolvedAfter != filepath.Clean(path) ||
		pathAfter.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, after) || !os.SameFile(after, pathAfter) ||
		after.Size() != opened.Size() || after.Mode() != opened.Mode() {
		return "", errors.New("supervised executable drifted during read")
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func canonicalExecutable(path, root string) (string, string, error) {
	if !filepath.IsAbs(path) || !filepath.IsAbs(root) {
		return "", "", errors.New("supervisor paths must be absolute")
	}
	path, root = filepath.Clean(path), filepath.Clean(root)
	rootInfo, rootErr := os.Lstat(root)
	pathInfo, pathErr := os.Lstat(path)
	if rootErr != nil || pathErr != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 ||
		!pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 {
		return "", "", errors.New("supervisor paths are not ordinary targets")
	}
	resolvedRoot, rootErr := filepath.EvalSymlinks(root)
	resolvedPath, pathErr := filepath.EvalSymlinks(path)
	if rootErr != nil || pathErr != nil || resolvedRoot != root || resolvedPath != path ||
		!strings.HasPrefix(path, root+string(filepath.Separator)) {
		return "", "", errors.New("supervised executable is outside the exact clone root")
	}
	return path, root, nil
}

func (value *Frame) validateInit() error {
	if value == nil {
		return errors.New("supervisor init frame is invalid")
	}
	if value.Version != ProtocolVersion || value.Type != "init" ||
		(value.Mode != "synthetic" && value.Mode != "preexec") ||
		value.LeaseDeadlineNS == 0 || !validDigest(value.ExecutableDigest) || value.PID != 0 || value.StartNS != 0 ||
		value.SupervisorPID != 0 || value.SupervisorStartNS != 0 || !validDigest(value.SupervisorDigest) ||
		value.ErrorCode != "" || len(value.Arguments) > 16 {
		return errors.New("supervisor init frame is invalid")
	}
	for _, argument := range value.Arguments {
		if len(argument) > 1024 || strings.ContainsAny(argument, "\x00\r\n") {
			return errors.New("supervisor argument is invalid")
		}
	}
	executable, cloneRoot, err := canonicalExecutable(value.Executable, value.CloneRoot)
	if err != nil {
		return err
	}
	digest, err := digestFile(executable)
	if err != nil || digest != value.ExecutableDigest {
		return errors.New("supervised executable digest changed")
	}
	value.Executable, value.CloneRoot = executable, cloneRoot
	return nil
}

func (value Frame) validateControl(bound Frame) error {
	if value.Version != ProtocolVersion || (value.Type != "release" && value.Type != "stop") ||
		value.Mode != "" || value.LeaseDeadlineNS != 0 || value.Executable != "" || value.CloneRoot != "" ||
		value.ExecutableDigest != "" || len(value.Arguments) != 0 || value.ErrorCode != "" ||
		value.SupervisorPID != 0 || value.SupervisorStartNS != 0 || value.SupervisorDigest != "" ||
		value.PID != bound.PID || value.StartNS != bound.StartNS {
		return errors.New("supervisor control frame does not bind the owned process")
	}
	return nil
}

func (value Frame) validatePrepare(supervisor Frame) error {
	if value.Version != ProtocolVersion || value.Type != "prepare" || value.Mode != "" ||
		value.LeaseDeadlineNS != 0 || value.Executable != "" || value.CloneRoot != "" ||
		value.ExecutableDigest != "" || len(value.Arguments) != 0 || value.PID != 0 || value.StartNS != 0 ||
		value.ErrorCode != "" || value.SupervisorPID != supervisor.SupervisorPID ||
		value.SupervisorStartNS != supervisor.SupervisorStartNS || value.SupervisorDigest != supervisor.SupervisorDigest {
		return errors.New("supervisor prepare frame does not bind the persisted supervisor")
	}
	return nil
}

func (value Frame) validateSupervisorBound(expectedPID int, expectedDigest string) error {
	if expectedPID <= 0 || !validDigest(expectedDigest) || value.Version != ProtocolVersion ||
		value.Type != "supervisor_bound" || value.Mode != "" || value.LeaseDeadlineNS != 0 ||
		value.Executable != "" || value.CloneRoot != "" || value.ExecutableDigest != "" ||
		len(value.Arguments) != 0 || value.PID != 0 || value.StartNS != 0 || value.SupervisorPID != expectedPID ||
		value.SupervisorStartNS == 0 || value.SupervisorDigest != expectedDigest || value.ErrorCode != "" {
		return errors.New("supervisor returned an invalid self binding")
	}
	return nil
}

func (value Frame) validateBound(init, supervisor Frame) error {
	if value.Version != ProtocolVersion || value.Type != "bound" || value.Mode != "" ||
		value.LeaseDeadlineNS != init.LeaseDeadlineNS || value.Executable != init.Executable ||
		value.CloneRoot != init.CloneRoot || value.ExecutableDigest != init.ExecutableDigest ||
		len(value.Arguments) != 0 || value.PID <= 0 || value.StartNS == 0 ||
		value.SupervisorPID != supervisor.SupervisorPID ||
		value.SupervisorStartNS != supervisor.SupervisorStartNS ||
		value.SupervisorDigest != supervisor.SupervisorDigest || value.SupervisorPID == value.PID ||
		value.ErrorCode != "" {
		return errors.New("supervisor returned an invalid process binding")
	}
	return nil
}

func (value Frame) validateAcknowledgement(kind string, bound Frame) error {
	if (kind != "released" && kind != "stopped") || value.Version != ProtocolVersion || value.Type != kind ||
		value.Mode != "" || value.LeaseDeadlineNS != 0 || value.Executable != "" || value.CloneRoot != "" ||
		value.ExecutableDigest != "" || len(value.Arguments) != 0 || value.PID != bound.PID ||
		value.StartNS != bound.StartNS || value.SupervisorPID != 0 || value.SupervisorStartNS != 0 ||
		value.SupervisorDigest != "" || value.ErrorCode != "" {
		return errors.New("supervisor returned an invalid acknowledgement")
	}
	return nil
}

func readFrame(reader io.Reader) (Frame, error) {
	payload, err := io.ReadAll(io.LimitReader(reader, maxFrameBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > maxFrameBytes {
		return Frame{}, errors.New("supervisor control frame is empty or oversized")
	}
	var frame Frame
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&frame); err != nil {
		return Frame{}, errors.New("supervisor control frame is invalid JSON")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Frame{}, errors.New("supervisor control frame has trailing data")
	}
	return frame, nil
}

func writeFrame(writer io.Writer, frame Frame) error {
	payload, err := json.Marshal(frame)
	if err != nil || len(payload) > maxFrameBytes {
		return errors.New("supervisor response frame is invalid")
	}
	payload = append(payload, '\n')
	for len(payload) > 0 {
		written, writeErr := writer.Write(payload)
		if writeErr != nil {
			return writeErr
		}
		if written <= 0 || written > len(payload) {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}
