package darwin

import (
	"path/filepath"
	"strconv"
	"strings"
)

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
