//go:build windows

package shadowcleanup

import (
	"context"
	"errors"

	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
)

type Qualification struct {
	Route               string
	NestedRemoved       bool
	ReplacementRejected bool
}

func BindDirectory(string, string, string) (contract.ResourceBinding, error) {
	return contract.ResourceBinding{}, errors.New("direct Shadow cleanup is unavailable on Windows")
}

func CreateExactDirectory(context.Context, string, string, string) (contract.ResourceBinding, error) {
	return contract.ResourceBinding{}, errors.New("direct Shadow cleanup is unavailable on Windows")
}

func RemoveExactDirectory(context.Context, string, contract.ResourceBinding) error {
	return errors.New("direct Shadow cleanup is unavailable on Windows")
}

func QualifyDirect(context.Context, string) (Qualification, error) {
	return Qualification{}, errors.New("direct Shadow cleanup is unavailable on Windows")
}
