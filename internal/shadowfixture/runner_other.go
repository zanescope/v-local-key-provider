//go:build !darwin

package shadowfixture

import commandmodel "github.com/zanescope/v-local-key-provider/internal/command"

func NewRunner() commandmodel.ShadowRunner { return nil }
