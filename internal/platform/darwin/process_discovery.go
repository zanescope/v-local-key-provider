package darwin

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type OutputRunner func(context.Context, string, []string, int) ([]byte, error)

type ProcessDiscoveryError struct {
	PS        error
	Launchctl error
}

func (err *ProcessDiscoveryError) Error() string {
	return fmt.Sprintf("读取微信进程列表失败：ps=%v；launchctl=%v", err.PS, err.Launchctl)
}

type Process struct {
	PID     int
	Name    string
	Command string
}

func IsWeChatProcess(name, command string) bool {
	baseName := strings.ToLower(filepath.Base(name))
	lowerCommand := strings.ToLower(command)
	if baseName == "wechatappex" || strings.Contains(lowerCommand, "wechatappex") ||
		strings.Contains(lowerCommand, "crashpad_handler") || strings.Contains(lowerCommand, "helper") {
		return false
	}
	if baseName == "wechat" || baseName == "weixin" || baseName == "微信" {
		return true
	}
	return strings.Contains(lowerCommand, "/contents/macos/wechat") ||
		strings.Contains(lowerCommand, "/contents/macos/weixin") ||
		strings.Contains(lowerCommand, "/contents/macos/微信")
}

func ParseProcessList(output string) []Process {
	seen := map[int]bool{}
	processes := []Process{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil || pid <= 0 || seen[pid] {
			continue
		}
		name := fields[1]
		command := strings.Join(fields[2:], " ")
		if !IsWeChatProcess(name, command) {
			continue
		}
		seen[pid] = true
		processes = append(processes, Process{PID: pid, Name: name, Command: command})
	}
	return processes
}

func ParseLaunchctlProcessList(output string) []Process {
	processes := []Process{}
	seen := map[int]bool{}
	depth := 0
	bundleID := ""
	program := ""
	pid := 0
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if depth == 0 && strings.HasSuffix(trimmed, "= {") {
			depth = 1
			bundleID, program, pid = "", "", 0
			continue
		}
		if depth == 0 {
			continue
		}
		if strings.HasPrefix(trimmed, "bundle id = ") {
			bundleID = strings.TrimSpace(strings.TrimPrefix(trimmed, "bundle id = "))
		}
		if strings.HasPrefix(trimmed, "program = ") {
			program = strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "program = ")), "\"")
		}
		if strings.HasPrefix(trimmed, "pid = ") {
			pid, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(trimmed, "pid = ")))
		}
		for _, value := range trimmed {
			switch value {
			case '{':
				depth++
			case '}':
				depth--
			}
		}
		if depth == 0 && bundleID == "com.tencent.xinWeChat" && pid > 0 && program != "" && !seen[pid] {
			seen[pid] = true
			processes = append(processes, Process{PID: pid, Name: filepath.Base(program), Command: program})
		}
	}
	return processes
}

type ProcessRef struct {
	Label string
	PID   int
}

func ParseLaunchctlProcessRefs(output string) []ProcessRef {
	refs := []ProcessRef{}
	seen := map[int]bool{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil || pid <= 0 || seen[pid] {
			continue
		}
		label := fields[len(fields)-1]
		if !strings.HasPrefix(label, "application.com.tencent.xinWeChat.") || strings.Contains(label, "WeChatAppEx") {
			continue
		}
		seen[pid] = true
		refs = append(refs, ProcessRef{Label: label, PID: pid})
	}
	return refs
}

// DiscoverProcesses 持有有界的 ps -> launchctl fallback 策略；composition root 提供经过
// 加固的子进程 runner 和 buffer 清理器。
func DiscoverProcesses(run OutputRunner, clear func([]byte), uid int) ([]Process, string, error) {
	if run == nil {
		return nil, "unavailable", errors.New("Darwin process command runner is unavailable")
	}
	if clear == nil {
		clear = func(value []byte) {
			for index := range value {
				value[index] = 0
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	output, err := run(ctx, "/bin/ps", []string{"-axo", "pid=,comm=,args="}, 8*1024*1024)
	defer clear(output)
	if err == nil {
		return ParseProcessList(string(output)), "ps", nil
	}
	uidText := strconv.Itoa(uid)
	launchOutput, launchErr := run(ctx, "/bin/launchctl", []string{"print", "gui/" + uidText}, 8*1024*1024)
	defer clear(launchOutput)
	if launchErr == nil {
		processes := ParseLaunchctlProcessList(string(launchOutput))
		seen := map[int]bool{}
		for _, process := range processes {
			seen[process.PID] = true
		}
		refs := ParseLaunchctlProcessRefs(string(launchOutput))
		var detailErr error
		for _, ref := range refs {
			if seen[ref.PID] {
				continue
			}
			detail, commandErr := run(
				ctx, "/bin/launchctl", []string{"print", "gui/" + uidText + "/" + ref.Label}, 1024*1024,
			)
			if commandErr != nil {
				clear(detail)
				if detailErr == nil {
					detailErr = commandErr
				}
				continue
			}
			parsed := ParseLaunchctlProcessList(string(detail))
			clear(detail)
			for _, process := range parsed {
				if process.PID != ref.PID || seen[process.PID] {
					continue
				}
				seen[process.PID] = true
				processes = append(processes, process)
			}
		}
		if len(processes) == 0 && len(refs) > 0 {
			if detailErr == nil {
				detailErr = errors.New("微信应用服务详情不可读")
			}
			return nil, "launchctl", &ProcessDiscoveryError{PS: err, Launchctl: detailErr}
		}
		return processes, "launchctl", nil
	}
	return nil, "ps_then_launchctl", &ProcessDiscoveryError{PS: err, Launchctl: launchErr}
}
