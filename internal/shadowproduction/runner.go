//go:build darwin

package shadowproduction

import (
	"context"
	"errors"

	shadowmodel "github.com/zanescope/v-local-key-provider/internal/shadow"
	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
)

// QualificationRunner exposes only the immutable, read-only qualification
// half of a production build. Execute remains disabled until every ordered
// machine gate has been accepted for this exact build-set digest.
type QualificationRunner struct {
	Prelaunch *Prelaunch
}

func (value QualificationRunner) Qualify(ctx context.Context, request contract.Request) (shadowmodel.Output, error) {
	if value.Prelaunch == nil || request.Validate() != nil || request.Operation != "qualify" {
		return shadowmodel.Output{}, errors.New("production qualification request is invalid")
	}
	qualification, _, err := value.Prelaunch.Qualify(ctx, request)
	if err != nil {
		code := contract.ErrorSourceDrift
		var failure *shadowmodel.Failure
		if errors.As(err, &failure) {
			code = failure.Code
		}
		result := contract.Result{
			Version: contract.Version, RequestID: request.RequestID, Status: "failed",
			ErrorCode: code,
		}
		return shadowmodel.Output{Result: result}, result.Validate()
	}
	qualification.ProductionRouteEnabled = false
	result := contract.Result{
		Version: contract.Version, RequestID: request.RequestID, Status: "qualified",
		ErrorCode: contract.ErrorNone, Qualification: &qualification,
	}
	return shadowmodel.Output{Result: result}, result.Validate()
}

func (value QualificationRunner) Execute(_ context.Context, request contract.Request) (shadowmodel.Output, error) {
	if request.Validate() != nil || request.Operation != "execute" {
		return shadowmodel.Output{}, errors.New("production execution request is invalid")
	}
	result := contract.Result{
		Version: contract.Version, RequestID: request.RequestID, Status: "failed",
		ErrorCode: contract.ErrorProductionRouteDisabled,
	}
	return shadowmodel.Output{Result: result}, result.Validate()
}
