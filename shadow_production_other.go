//go:build !darwin

package provider

import commandmodel "github.com/zanescope/v-local-key-provider/internal/command"

func productionQualificationRunner() (commandmodel.ShadowRunner, string) { return nil, "" }
