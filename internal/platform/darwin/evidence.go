package darwin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type CombinedOutputRunner func(context.Context, string, []string, int) ([]byte, error)

// EvidenceRuntime 把进程和二进制信任机制保留在 Provider composition 边界，而 Darwin
// 证据策略由本 package 持有。
type EvidenceRuntime struct {
	RunOutput             OutputRunner
	RunCombinedOutput     CombinedOutputRunner
	ProcessExecutablePath func(uint32) (string, error)
	ExecutableSHA256      func(string) string
	PathIsLinkOrReparse   func(string, fs.FileMode) (bool, error)
	SameCanonicalPath     func(string, string) bool
	ClearSensitive        func([]byte)
}

type EvidenceCollector struct {
	runtime EvidenceRuntime
}

func NewEvidenceCollector(runtimeConfig EvidenceRuntime) *EvidenceCollector {
	return &EvidenceCollector{runtime: runtimeConfig}
}

func isAbsoluteProcessPath(value string) bool {
	return strings.HasPrefix(value, "/") || filepath.IsAbs(value)
}

func cleanProcessPath(value string) string {
	if strings.HasPrefix(value, "/") {
		return path.Clean(value)
	}
	return filepath.Clean(value)
}

func processBase(value string) string {
	return path.Base(filepath.ToSlash(value))
}

func (collector *EvidenceCollector) clear(value []byte) {
	if collector != nil && collector.runtime.ClearSensitive != nil {
		collector.runtime.ClearSensitive(value)
		return
	}
	for index := range value {
		value[index] = 0
	}
}

func (collector *EvidenceCollector) ProcessExecutable(process Process) string {
	if process.PID > 0 && collector != nil && collector.runtime.ProcessExecutablePath != nil {
		if executable, err := collector.runtime.ProcessExecutablePath(uint32(process.PID)); err == nil && isAbsoluteProcessPath(executable) {
			return cleanProcessPath(executable)
		}
	}
	command := strings.TrimSpace(process.Command)
	if command == "" {
		command = process.Name
	}
	for _, suffix := range []string{"/Contents/MacOS/WeChat", "/Contents/MacOS/Weixin", "/Contents/MacOS/微信"} {
		if marker := strings.Index(command, suffix); marker >= 0 {
			candidate := strings.Trim(strings.TrimSpace(command[:marker+len(suffix)]), "'\"")
			if isAbsoluteProcessPath(candidate) {
				return cleanProcessPath(candidate)
			}
		}
	}
	if fields := strings.Fields(command); len(fields) > 0 {
		candidate := strings.Trim(fields[0], "'\"")
		if isAbsoluteProcessPath(candidate) {
			return cleanProcessPath(candidate)
		}
	}
	if isAbsoluteProcessPath(process.Name) {
		return cleanProcessPath(process.Name)
	}
	return ""
}

func (collector *EvidenceCollector) plistValue(process Process, key string) string {
	executable := collector.ProcessExecutable(process)
	slashExecutable := filepath.ToSlash(executable)
	marker := strings.Index(slashExecutable, ".app/Contents/")
	if marker < 0 || collector == nil || collector.runtime.RunOutput == nil {
		return ""
	}
	appPath := filepath.FromSlash(slashExecutable[:marker+len(".app")])
	plist := filepath.Join(appPath, "Contents", "Info.plist")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	output, err := collector.runtime.RunOutput(ctx, "/usr/libexec/PlistBuddy", []string{"-c", "Print:" + key, plist}, 16*1024)
	defer collector.clear(output)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func (collector *EvidenceCollector) ProcessVersion(process Process) string {
	return collector.plistValue(process, "CFBundleShortVersionString")
}

func (collector *EvidenceCollector) ProcessBuild(process Process) string {
	return collector.plistValue(process, "CFBundleVersion")
}

func (collector *EvidenceCollector) ProcessArchitectureEvidence(process Process) (string, string, string) {
	if process.PID <= 0 {
		return "unknown", ArchitectureNotEvaluated, "not_evaluated"
	}
	if collector == nil || collector.runtime.RunOutput == nil {
		return "unknown", ArchitectureUnavailable, "unknown"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	output, err := collector.runtime.RunOutput(ctx, "/bin/ps", []string{"-p", strconv.Itoa(process.PID), "-o", "arch="}, 4*1024)
	defer collector.clear(output)
	if err != nil {
		return "unknown", ArchitectureUnavailable, "unknown"
	}
	architecture := NormalizeArchitecture(string(output))
	if architecture == "unknown" {
		return architecture, ArchitectureUnavailable, "unknown"
	}
	machineOutput, machineErr := collector.runtime.RunOutput(ctx, "/usr/bin/uname", []string{"-m"}, 4*1024)
	defer collector.clear(machineOutput)
	translation := "unknown"
	if machineErr == nil {
		translation = TranslationStatus(architecture, string(machineOutput))
	}
	return architecture, ArchitectureVerified, translation
}

func (collector *EvidenceCollector) ProcessArchitecture(process Process) string {
	architecture, _, _ := collector.ProcessArchitectureEvidence(process)
	return architecture
}

func (collector *EvidenceCollector) macOSVersion() string {
	if collector == nil || collector.runtime.RunOutput == nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	output, err := collector.runtime.RunOutput(ctx, "/usr/bin/sw_vers", []string{"-productVersion"}, 4*1024)
	defer collector.clear(output)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func (collector *EvidenceCollector) codeSigningEvidence(executable string) (string, string, string) {
	if executable == "" {
		return SigningNotEvaluated, "", ""
	}
	if collector == nil || collector.runtime.PathIsLinkOrReparse == nil || collector.runtime.RunCombinedOutput == nil {
		return SigningUnavailable, "", ""
	}
	info, err := os.Lstat(executable)
	unsafePath := false
	if err == nil {
		unsafePath, err = collector.runtime.PathIsLinkOrReparse(executable, info.Mode())
	}
	if err != nil || unsafePath || !info.Mode().IsRegular() {
		return SigningUnavailable, "", ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	verification, verifyErr := collector.runtime.RunCombinedOutput(
		ctx, "/usr/bin/codesign", []string{"--verify", "--strict", "--verbose=4", executable}, 64*1024,
	)
	collector.clear(verification)
	if verifyErr != nil || ctx.Err() != nil {
		return SigningInvalid, "", ""
	}
	details, detailsErr := collector.runtime.RunCombinedOutput(
		ctx, "/usr/bin/codesign", []string{"-dv", "--verbose=4", executable}, 64*1024,
	)
	defer collector.clear(details)
	if detailsErr != nil || ctx.Err() != nil {
		return SigningUnavailable, "", ""
	}
	teamID := ""
	for _, line := range strings.Split(string(details), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "TeamIdentifier=") {
			teamID = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "TeamIdentifier="))
			break
		}
	}
	if teamID == "" || len(teamID) > 64 || strings.ContainsAny(teamID, " \t\r\n") {
		return SigningInvalid, "", ""
	}
	requirement, requirementErr := collector.runtime.RunCombinedOutput(
		ctx, "/usr/bin/codesign", []string{"-dr", "-", executable}, 64*1024,
	)
	defer collector.clear(requirement)
	if requirementErr != nil || ctx.Err() != nil {
		return SigningUnavailable, "", ""
	}
	designated := ""
	for _, line := range strings.Split(string(requirement), "\n") {
		line = strings.TrimSpace(line)
		if marker := strings.Index(line, "designated =>"); marker >= 0 {
			designated = strings.TrimSpace(line[marker+len("designated =>"):])
			break
		}
	}
	if designated == "" {
		return SigningInvalid, "", ""
	}
	digest := sha256.Sum256([]byte(designated))
	return SigningVerified, teamID, hex.EncodeToString(digest[:])
}

func (collector *EvidenceCollector) CollectEvidence(process Process) BinaryEvidence {
	evidence := BinaryEvidence{
		BinaryFingerprintStatus:   FingerprintNotEvaluated,
		BinarySigningStatus:       SigningNotEvaluated,
		ProcessArchitecture:       "unknown",
		ProcessArchitectureStatus: ArchitectureNotEvaluated,
		ProcessTranslationStatus:  "not_evaluated",
	}
	evidence.Version = collector.ProcessVersion(process)
	evidence.Build = collector.ProcessBuild(process)
	evidence.MacOSVersion = collector.macOSVersion()
	evidence.MacOSMajorMinor = MajorMinor(evidence.MacOSVersion)
	evidence.ProcessArchitecture, evidence.ProcessArchitectureStatus, evidence.ProcessTranslationStatus =
		collector.ProcessArchitectureEvidence(process)
	executable := collector.ProcessExecutable(process)
	if executable == "" {
		return evidence
	}
	if collector != nil && collector.runtime.ExecutableSHA256 != nil {
		evidence.ExecutableSHA256 = collector.runtime.ExecutableSHA256(executable)
	}
	if ValidSHA256(evidence.ExecutableSHA256) {
		evidence.BinaryFingerprintStatus = FingerprintVerified
	} else {
		evidence.ExecutableSHA256 = ""
		evidence.BinaryFingerprintStatus = FingerprintUnavailable
	}
	evidence.BinarySigningStatus, evidence.SigningTeamID, evidence.DesignatedRequirementSHA256 =
		collector.codeSigningEvidence(executable)
	return evidence
}

func (collector *EvidenceCollector) PrelaunchProcess() Process {
	process := Process{}
	process.Command = collector.WeChatExecutable(process)
	process.Name = processBase(process.Command)
	return process
}

func (collector *EvidenceCollector) WeChatExecutable(process Process) string {
	if executable := collector.ProcessExecutable(process); executable != "" {
		return executable
	}
	candidates := []string{
		"/Applications/WeChat.app/Contents/MacOS/WeChat",
		"/Applications/Weixin.app/Contents/MacOS/Weixin",
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, "Applications", "WeChat.app", "Contents", "MacOS", "WeChat"),
			filepath.Join(home, "Applications", "Weixin.app", "Contents", "MacOS", "Weixin"),
		)
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

func WaitForProcessName(executable string) string {
	if strings.EqualFold(processBase(executable), "weixin") || strings.Contains(strings.ToLower(executable), "weixin.app") {
		return "Weixin"
	}
	return "WeChat"
}

func (collector *EvidenceCollector) LLDBPath() string {
	const path = "/usr/bin/lldb"
	if collector == nil || collector.runtime.SameCanonicalPath == nil {
		return ""
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode()&0o111 == 0 {
		return ""
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !collector.runtime.SameCanonicalPath(path, resolved) {
		return ""
	}
	return path
}

func (collector *EvidenceCollector) ProcessInstanceID(driver NativeDriver) string {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if driver == nil {
		return "darwin:process-list-unavailable"
	}
	processes, _, err := driver.ListProcesses()
	if err != nil {
		return "darwin:process-list-unavailable"
	}
	identities := make([]string, 0, len(processes))
	for _, process := range processes {
		var started []byte
		if collector != nil && collector.runtime.RunOutput != nil {
			started, _ = collector.runtime.RunOutput(
				ctx, "/bin/ps", []string{"-p", strconv.Itoa(process.PID), "-o", "lstart="}, 4*1024,
			)
		}
		executable := collector.ProcessExecutable(process)
		digest := ""
		if collector != nil && collector.runtime.ExecutableSHA256 != nil {
			digest = collector.runtime.ExecutableSHA256(executable)
		}
		identities = append(identities, fmt.Sprintf("%d:%s:%s:%s:%s:%s",
			process.PID, strings.TrimSpace(string(started)), executable,
			collector.ProcessArchitecture(process), collector.ProcessVersion(process), digest))
		collector.clear(started)
	}
	sort.Strings(identities)
	sum := sha256.Sum256([]byte(strings.Join(identities, "\x00")))
	return "darwin:" + hex.EncodeToString(sum[:16])
}
