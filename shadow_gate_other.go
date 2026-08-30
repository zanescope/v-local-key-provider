//go:build !darwin

package provider

import "io"

func runShadowGateCommand([]string, io.Writer) (bool, int) { return false, 0 }
