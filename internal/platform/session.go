// Package platform 定义与各 OS 采集实现交换的共享证据。原生 collector 仍位于子 package
// 或带 build tag 的命令 adapter 中。
package platform

type HookSnapshot struct {
	TargetFound      int
	Installed        bool
	TimedOut         bool
	TriggerNeeded    bool
	RestartNeeded    bool
	Captures         int
	Used             bool
	Route            string
	RouteHistory     string
	IdentityRejected bool
}
