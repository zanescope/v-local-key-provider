// Package platform defines shared evidence exchanged with OS-specific
// acquisition implementations. Native collectors remain in child packages or
// build-tagged command adapters.
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
