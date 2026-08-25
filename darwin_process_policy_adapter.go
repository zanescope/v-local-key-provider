//go:build darwin && cgo

package provider

import darwinmodel "github.com/zanescope/v-local-key-provider/internal/platform/darwin"

type darwinProcess struct {
	pid     int
	name    string
	command string
}

func darwinProcessFromModel(process darwinmodel.Process) darwinProcess {
	return darwinProcess{pid: process.PID, name: process.Name, command: process.Command}
}

func darwinProcessToModel(process darwinProcess) darwinmodel.Process {
	return darwinmodel.Process{PID: process.pid, Name: process.name, Command: process.command}
}

func parseDarwinProcessList(output string) []darwinProcess {
	models := darwinmodel.ParseProcessList(output)
	processes := make([]darwinProcess, 0, len(models))
	for _, process := range models {
		processes = append(processes, darwinProcessFromModel(process))
	}
	return processes
}

func isDarwinWeChatProcess(name, command string) bool {
	return darwinmodel.IsWeChatProcess(name, command)
}

func parseLaunchctlProcessList(output string) []darwinProcess {
	models := darwinmodel.ParseLaunchctlProcessList(output)
	processes := make([]darwinProcess, 0, len(models))
	for _, process := range models {
		processes = append(processes, darwinProcessFromModel(process))
	}
	return processes
}

type launchctlProcessRef struct {
	label string
	pid   int
}

func parseLaunchctlProcessRefs(output string) []launchctlProcessRef {
	models := darwinmodel.ParseLaunchctlProcessRefs(output)
	refs := make([]launchctlProcessRef, 0, len(models))
	for _, ref := range models {
		refs = append(refs, launchctlProcessRef{label: ref.Label, pid: ref.PID})
	}
	return refs
}
