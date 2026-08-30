//go:build !darwin

package shadowworkspace

func New() Runtime { return Runtime{} }
