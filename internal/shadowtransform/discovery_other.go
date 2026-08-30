//go:build !darwin

package shadowtransform

import (
	"context"
	"errors"
)

func Discover(context.Context, string, DiscoveryInput) (Discovery, error) {
	return Discovery{}, errors.New("Shadow transformation discovery is only available on macOS")
}
