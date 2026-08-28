package provider

import (
	acquisitionmodel "github.com/zanescope/v-local-key-provider/internal/acquisition"
	platformmodel "github.com/zanescope/v-local-key-provider/internal/platform"
)

type platformHookSnapshot = platformmodel.HookSnapshot

func newSynchronizedPlatformSession(
	collect func(*candidateCollector) platformHookSnapshot,
	status func() platformHookSnapshot,
	close func(),
) acquisitionPlatformSession {
	return acquisitionmodel.NewSynchronizedPlatformSession(collect, status, close)
}
