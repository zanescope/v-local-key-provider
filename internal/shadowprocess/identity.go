// Package shadowprocess exposes the OS-observed process birth identity used to
// reject PID reuse. The value is in the same monotonic nanosecond domain across
// independent observations of one boot.
package shadowprocess

import "errors"

func StartMonotonicNS(pid int) (uint64, error) {
	if pid <= 0 {
		return 0, errors.New("Shadow process PID is invalid")
	}
	value, found, err := systemStartMonotonicNS(pid)
	if err != nil || !found || value == 0 {
		return 0, errors.New("Shadow process start identity is unavailable")
	}
	return value, nil
}

// Absent reports whether the exact PID/birth pair is gone. A live process with
// the same PID and another birth identity is PID reuse, so the original process
// is absent. Query failures remain uncertain and fail closed.
func Absent(pid int, expectedStartNS uint64) (bool, error) {
	if pid <= 0 || expectedStartNS == 0 {
		return false, errors.New("Shadow process absence binding is invalid")
	}
	value, found, err := systemStartMonotonicNS(pid)
	if err != nil {
		return false, errors.New("Shadow process absence is uncertain")
	}
	return !found || value != expectedStartNS, nil
}
