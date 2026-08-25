package main

import (
	"os"

	provider "github.com/zanescope/v-local-key-provider"
)

var (
	version                = "0.1.0-dev.0"
	buildMode              = "development"
	releaseSignerSHA256    string
	releasePromotionSHA256 string
)

func main() {
	os.Exit(provider.Run(provider.BuildConfig{
		Version: version, Mode: buildMode,
		ReleaseSignerSHA256: releaseSignerSHA256, ReleasePromotionSHA256: releasePromotionSHA256,
	}))
}
