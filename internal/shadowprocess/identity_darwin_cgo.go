//go:build darwin && cgo

package shadowprocess

/*
#cgo LDFLAGS: -lproc
#include <errno.h>
#include <libproc.h>
#include <mach/mach_time.h>
#include <stdint.h>
#include <sys/resource.h>

static int vl_process_start_ns(int pid, uint64_t *output) {
    struct rusage_info_v2 usage = {0};
    if (proc_pid_rusage(pid, RUSAGE_INFO_V2, (rusage_info_t *)&usage) != 0) {
        return errno == 0 ? EIO : errno;
    }
    mach_timebase_info_data_t timebase = {0};
    if (mach_timebase_info(&timebase) != KERN_SUCCESS || timebase.numer == 0 || timebase.denom == 0 ||
        usage.ri_proc_start_abstime == 0) {
        return EIO;
    }
    __uint128_t scaled = (__uint128_t)usage.ri_proc_start_abstime * timebase.numer;
    scaled /= timebase.denom;
    if (scaled == 0 || scaled > UINT64_MAX) {
        return EOVERFLOW;
    }
    *output = (uint64_t)scaled;
    return 0;
}
*/
import "C"

import "errors"

func systemStartMonotonicNS(pid int) (uint64, bool, error) {
	var value C.uint64_t
	if status := C.vl_process_start_ns(C.int(pid), &value); status == C.ESRCH {
		return 0, false, nil
	} else if status != 0 {
		return 0, false, errors.New("macOS process start identity query failed")
	}
	return uint64(value), true, nil
}
