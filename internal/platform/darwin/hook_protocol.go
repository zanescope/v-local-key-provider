package darwin

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var darwinLLDBBreakpointPattern = regexp.MustCompile(`(?m)^Breakpoint [0-9]+:`)

func LLDBBreakpointCount(output string) int {
	count := 0
	for _, line := range strings.Split(output, "\n") {
		if !darwinLLDBBreakpointPattern.MatchString(line) || strings.Contains(strings.ToLower(line), "no locations") {
			continue
		}
		count++
	}
	return count
}

// darwinHookPythonSource 使用 LLDB 的 Python 回调接口。所有捕获标记只写入由提供器
// 捕获的标准输出，不落普通临时文件。在 x86_64 上，
// CCCryptorCreateWithMode 的密钥长度是第 7 个参数，因此落在 [rsp+8]；
// 若把 r8/r9 当作 key/keyLength 参数，会误读到初始化向量。
func HookPythonSource(architecture string) string {
	return fmt.Sprintf(`import lldb

_seen = set()
_breakpoints = []
_expected_architecture = %q

def _append(line):
    print(line, flush=True)

def _register(frame, name):
    value = frame.FindRegister(name)
    return value.GetValueAsUnsigned() if value.IsValid() else 0

def _read(process, address, length):
    if address == 0 or length <= 0 or length > 256:
        return None
    error = lldb.SBError()
    data = process.ReadMemory(address, length, error)
    if not error.Success() or len(data) != length:
        return None
    return data.hex()

def _read_uint(process, address):
    raw = _read(process, address, 8)
    return int.from_bytes(bytes.fromhex(raw), "little") if raw else 0

def _frame_architecture(frame):
    target = frame.GetThread().GetProcess().GetTarget()
    triple = target.GetTriple().lower() if target.IsValid() else ""
    if "arm64" in triple or "aarch64" in triple:
        actual = "arm64"
    elif "x86_64" in triple or "amd64" in triple:
        actual = "amd64"
    else:
        return "unknown"
    if _expected_architecture not in ("auto", actual):
        return "unknown"
    return actual

def _emit(frame, key_address, key_length):
    if key_length != 32:
        return False
    key = _read(frame.GetThread().GetProcess(), key_address, 32)
    if key is not None and key not in _seen:
        _seen.add(key)
        _append("VLOCALPID=" + str(frame.GetThread().GetProcess().GetProcessID()))
        _append("VLOCALKEY32=" + key)
    return False

def _emit_pbkdf(frame, algorithm, password_address, password_length, salt_address, salt_length, prf, rounds, output_length):
    if password_length <= 0 or password_length > 256 or salt_length <= 0 or salt_length > 64 or output_length <= 0 or output_length > 256:
        return False
    process = frame.GetThread().GetProcess()
    password = _read(process, password_address, password_length)
    salt = _read(process, salt_address, salt_length)
    if password is None or salt is None:
        return False
    marker = "%%d,%%d,%%d,%%d,%%d,%%s,%%s" %% (algorithm, prf, rounds, password_length, output_length, password, salt)
    fingerprint = "PBKDF:" + marker
    if fingerprint not in _seen:
        _seen.add(fingerprint)
        _append("VLOCALPID=" + str(process.GetProcessID()))
        _append("VLOCALPBKDF=" + marker)
    return False

def _create_bp(target, name, callback):
    breakpoint = target.BreakpointCreateByName(name)
    breakpoint.SetScriptCallbackFunction(__name__ + "." + callback)
    return breakpoint

def _breakpoint_is_resolved(breakpoint):
    if not breakpoint.IsValid():
        return False
    resolved_count = getattr(breakpoint, "GetNumResolvedLocations", None)
    if resolved_count is not None:
        return resolved_count() > 0
    return breakpoint.GetNumLocations() > 0

def _report_hooks(debugger, command, result, internal_dict):
    installed = sum(1 for breakpoint in _breakpoints if _breakpoint_is_resolved(breakpoint))
    _append("VLOCALHOOKS=" + str(installed))

def cryptor_bp(frame, breakpoint_location, internal_dict):
    architecture = _frame_architecture(frame)
    if architecture == "arm64":
        return _emit(frame, _register(frame, "x3"), _register(frame, "x4"))
    if architecture == "amd64":
        return _emit(frame, _register(frame, "rcx"), _register(frame, "r8"))
    return False

def with_mode_bp(frame, breakpoint_location, internal_dict):
    architecture = _frame_architecture(frame)
    if architecture == "arm64":
        return _emit(frame, _register(frame, "x5"), _register(frame, "x6"))
    if architecture != "amd64":
        return False
    process = frame.GetThread().GetProcess()
    stack = _register(frame, "rsp")
    return _emit(frame, _register(frame, "r9"), _read_uint(process, stack + 8))

def pbkdf_bp(frame, breakpoint_location, internal_dict):
    process = frame.GetThread().GetProcess()
    architecture = _frame_architecture(frame)
    if architecture == "arm64":
        stack = _register(frame, "sp")
        return _emit_pbkdf(frame, _register(frame, "x0"), _register(frame, "x1"), _register(frame, "x2"), _register(frame, "x3"), _register(frame, "x4"), _register(frame, "x5"), _register(frame, "x6"), _read_uint(process, stack))
    if architecture != "amd64":
        return False
    stack = _register(frame, "rsp")
    return _emit_pbkdf(frame, _register(frame, "rdi"), _register(frame, "rsi"), _register(frame, "rdx"), _register(frame, "rcx"), _register(frame, "r8"), _register(frame, "r9"), _read_uint(process, stack + 8), _read_uint(process, stack + 24))

def __lldb_init_module(debugger, internal_dict):
    global _breakpoints
    target = debugger.GetSelectedTarget()
    if not target.IsValid():
        return
    _breakpoints = [
        _create_bp(target, "CCCrypt", "cryptor_bp"),
        _create_bp(target, "CCCryptorCreate", "cryptor_bp"),
        _create_bp(target, "CCCryptorCreateWithMode", "with_mode_bp"),
        _create_bp(target, "CCKeyDerivationPBKDF", "pbkdf_bp"),
    ]
    debugger.HandleCommand("command script add -f " + __name__ + "._report_hooks vlocal-report-hooks")
    _report_hooks(debugger, "", None, internal_dict)
`, architecture)
}

func HookCommandFileWithPython(waitFor bool, executable, pythonPath, waitProcessName string) string {
	commands := []string{
		"settings set auto-confirm true",
		"settings set target.process.stop-on-sharedlibrary-events false",
		"settings set stop-disassembly-display never",
	}
	if waitFor {
		if executable != "" {
			commands = append(commands, fmt.Sprintf("target create %q", executable))
		}
		commands = append(commands,
			fmt.Sprintf("command script import %q", pythonPath),
			fmt.Sprintf("process attach --name %s --waitfor", waitProcessName),
			"vlocal-report-hooks",
			"process continue",
		)
		return strings.Join(commands, "\n") + "\n"
	}
	commands = append(commands,
		fmt.Sprintf("command script import %q", pythonPath),
		"vlocal-report-hooks",
		"process continue",
	)
	return strings.Join(commands, "\n") + "\n"
}

var darwinHookPythonKeyPattern = regexp.MustCompile(`(?m)^VLOCALKEY32=([0-9a-fA-F]{64})\s*$`)
var darwinHookPythonCountPattern = regexp.MustCompile(`(?m)^VLOCALHOOKS=([0-9]+)\s*$`)
var darwinHookPythonPIDPattern = regexp.MustCompile(`(?m)^VLOCALPID=([0-9]+)\s*$`)
var darwinHookPythonPBKDFPattern = regexp.MustCompile(`(?m)^VLOCALPBKDF=([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9a-fA-F]+),([0-9a-fA-F]+)\s*$`)

type PBKDFCapture struct {
	Algorithm    int
	PRF          int
	Rounds       int
	Password     []byte
	Salt         []byte
	OutputLength int
}

func ParseHookPythonKeys(output string) [][]byte {
	var captures [][]byte
	for _, match := range darwinHookPythonKeyPattern.FindAllStringSubmatch(output, -1) {
		candidate, err := hex.DecodeString(match[1])
		if err == nil && len(candidate) == 32 {
			captures = append(captures, candidate)
		}
	}
	return captures
}

func HookPythonCount(output string) int {
	count := 0
	for _, match := range darwinHookPythonCountPattern.FindAllStringSubmatch(output, -1) {
		if len(match) != 2 {
			continue
		}
		value, _ := strconv.Atoi(match[1])
		if value > count {
			count = value
		}
	}
	return count
}

func ParsePBKDFCaptures(output string) []PBKDFCapture {
	var captures []PBKDFCapture
	for _, match := range darwinHookPythonPBKDFPattern.FindAllStringSubmatch(output, -1) {
		algorithm, _ := strconv.Atoi(match[1])
		prf, _ := strconv.Atoi(match[2])
		rounds, _ := strconv.Atoi(match[3])
		passwordLength, _ := strconv.Atoi(match[4])
		outputLength, _ := strconv.Atoi(match[5])
		password, passwordErr := hex.DecodeString(match[6])
		salt, saltErr := hex.DecodeString(match[7])
		if passwordErr == nil && saltErr == nil && len(password) == passwordLength && len(password) <= 256 && len(salt) > 0 && len(salt) <= 64 {
			captures = append(captures, PBKDFCapture{
				Algorithm: algorithm, PRF: prf, Rounds: rounds, Password: password, Salt: salt, OutputLength: outputLength,
			})
		}
	}
	return captures
}

func CapturedPIDs(output string) []int {
	seen := map[int]bool{}
	var result []int
	for _, match := range darwinHookPythonPIDPattern.FindAllStringSubmatch(output, -1) {
		pid, _ := strconv.Atoi(match[1])
		if pid > 0 && !seen[pid] {
			seen[pid] = true
			result = append(result, pid)
		}
	}
	return result
}

func HasKeyOrPBKDFCapture(output string) bool {
	return darwinHookPythonKeyPattern.MatchString(output) || darwinHookPythonPBKDFPattern.MatchString(output)
}
