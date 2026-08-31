package shadowsupervisor

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type chunkWriter struct {
	buffer bytes.Buffer
	limit  int
}

func (value *chunkWriter) Write(payload []byte) (int, error) {
	if value.limit == 0 {
		return 0, nil
	}
	if len(payload) > value.limit {
		payload = payload[:value.limit]
	}
	return value.buffer.Write(payload)
}

func TestWriteFrameCompletesShortWrites(t *testing.T) {
	writer := &chunkWriter{limit: 3}
	frame := Frame{Version: ProtocolVersion, Type: "stopped", PID: 7, StartNS: 11}
	if err := writeFrame(writer, frame); err != nil {
		t.Fatal(err)
	}
	decoded, err := readFrame(bytes.NewReader(writer.buffer.Bytes()))
	if err != nil || !reflect.DeepEqual(decoded, frame) {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
}

func TestWriteFrameRejectsZeroProgress(t *testing.T) {
	if err := writeFrame(&chunkWriter{}, Frame{Version: ProtocolVersion, Type: "stopped"}); err != io.ErrShortWrite {
		t.Fatalf("unexpected zero-progress result: %v", err)
	}
}

func TestValidateInitRetainsCanonicalizedPaths(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(root, "target")
	if err := os.WriteFile(executable, []byte("synthetic executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	digest, err := digestFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	separator := string(filepath.Separator)
	frame := Frame{
		Version: ProtocolVersion, Type: "init", Mode: "synthetic", LeaseDeadlineNS: 1,
		Executable: root + separator + "." + separator + "target",
		CloneRoot:  root + separator + ".", ExecutableDigest: digest,
		SupervisorDigest: digest,
	}
	if err := frame.validateInit(); err != nil {
		t.Fatal(err)
	}
	if frame.Executable != executable || frame.CloneRoot != root {
		t.Fatalf("canonical paths were not retained: %+v", frame)
	}
}
