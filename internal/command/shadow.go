package command

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"runtime"
	"strings"

	catalogmodel "github.com/zanescope/v-local-key-provider/internal/catalog"
	credentialmodel "github.com/zanescope/v-local-key-provider/internal/credential"
	cryptomodel "github.com/zanescope/v-local-key-provider/internal/crypto"
	diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"
	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
	shadowmodel "github.com/zanescope/v-local-key-provider/internal/shadow"
	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
)

type ShadowRunner interface {
	Qualify(context.Context, contract.Request) (shadowmodel.Output, error)
	Execute(context.Context, contract.Request) (shadowmodel.Output, error)
}

type shadowCredentialPayload struct {
	CatalogID          string                              `json:"catalog_id,omitempty"`
	CatalogEntries     []catalogmodel.Database             `json:"catalog_entries,omitempty"`
	DatabaseKeys       map[string]string                   `json:"database_keys,omitempty"`
	DatabaseProfiles   map[string]string                   `json:"database_profiles,omitempty"`
	DatabaseCredential *credentialmodel.DatabaseCredential `json:"database_credential,omitempty"`
	ImageKeys          *protocolmodel.ImageKeys            `json:"image_keys,omitempty"`
	Profiles           []cryptomodel.Summary               `json:"profiles,omitempty"`
}

func decodeShadowCredential(payload []byte) (shadowCredentialPayload, error) {
	if len(payload) == 0 || len(payload) > protocolmodel.MaxResponseBytes {
		return shadowCredentialPayload{}, errors.New("Shadow credential payload is empty or oversized")
	}
	var result shadowCredentialPayload
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return shadowCredentialPayload{}, errors.New("Shadow credential payload is invalid")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return shadowCredentialPayload{}, errors.New("Shadow credential payload has trailing data")
	}
	if len(result.DatabaseKeys) == 0 && result.DatabaseCredential == nil && result.ImageKeys == nil {
		return shadowCredentialPayload{}, errors.New("Shadow credential payload has no minimal credential")
	}
	return result, nil
}

func validShadowDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func shadowScopeSelection(scopes []string) (database, media bool, err error) {
	canonical := diagnosticmodel.CanonicalScopes(scopes)
	if len(canonical) == 0 || len(canonical) != len(scopes) {
		return false, false, errors.New("Shadow credential request scopes are empty, duplicated, or unknown")
	}
	for index := range canonical {
		if canonical[index] != scopes[index] {
			return false, false, errors.New("Shadow credential request scopes are not canonical")
		}
	}
	for _, scope := range canonical {
		database = database || scope == "database"
		media = media || scope == "media"
	}
	return database, media, nil
}

func validateShadowCredentialForScopes(request protocolmodel.AcquireRequest, value shadowCredentialPayload) error {
	database, media, err := shadowScopeSelection(request.Scopes)
	if err != nil {
		return err
	}
	if database {
		if !validShadowDigest(value.CatalogID) || len(value.CatalogEntries) == 0 ||
			(len(value.DatabaseKeys) == 0) == (value.DatabaseCredential == nil) {
			return errors.New("Shadow database credential evidence is incomplete or ambiguous")
		}
		if value.DatabaseCredential != nil && len(value.DatabaseProfiles) != 0 {
			return errors.New("Shadow structured database credential carried legacy profiles")
		}
	} else if value.CatalogID != "" || len(value.CatalogEntries) != 0 || len(value.DatabaseKeys) != 0 ||
		len(value.DatabaseProfiles) != 0 || value.DatabaseCredential != nil || len(value.Profiles) != 0 {
		return errors.New("Shadow response carried unrequested database credential data")
	}
	if media {
		if value.ImageKeys == nil {
			return errors.New("Shadow media credential evidence is missing")
		}
	} else if value.ImageKeys != nil {
		return errors.New("Shadow response carried unrequested media credential data")
	}
	return nil
}

func shadowRouteID() string {
	if runtime.GOARCH == "amd64" {
		return "darwin_amd64_shadow_dynamic"
	}
	return "darwin_arm64_shadow_dynamic"
}

func shadowDiagnostics(request protocolmodel.AcquireRequest, result contract.Result, credential *shadowCredentialPayload, attempted bool) diagnosticmodel.Diagnostics {
	operation := ""
	if request.Workflow.Shadow != nil {
		operation = request.Workflow.Shadow.Operation
	}
	posture := "not_evaluated"
	if operation == "execute" && result.Receipt != nil && result.Receipt.Cleanup.SecurityPostureExpected {
		posture = "sip_enabled_verified"
	}
	diag := diagnosticmodel.NewWithPlatformDefaults("darwin", request.Scopes, diagnosticmodel.PlatformDefaults{
		SecurityPostureStatus: posture, DarwinShadowRouteStatus: "not_evaluated",
	})
	diag.ShadowAttempt = &result
	diag.ActionStage = "shadow_qualification"
	diag.WorkflowStatus = "terminal"
	diag.ResultCode = "unsupported"
	diag.NextAction = "stop_and_report"
	if operation == "synthetic_execute" {
		diag.ActionStage = "shadow_synthetic"
	} else if operation == "execute" {
		diag.ActionStage = "shadow_ephemeral"
	}
	if attempted && operation == "execute" {
		diag.RoutesAttempted = []string{shadowRouteID()}
		diag.ShadowRouteStatus = "attempted_failed"
		diag.BlockingReasons = []string{"shadow_route_failed"}
	}
	switch {
	case result.Status == "qualified":
		diag.ShadowRouteStatus = "available"
		diag.ResultCode = "partial"
		diag.NextAction = "none"
	case result.Status == "ready":
		diag.ResultCode = "complete"
		diag.NextAction = "none"
		diag.SessionAccountStatus = "known_target"
		if operation == "execute" {
			diag.ShadowRouteStatus = "succeeded"
			diag.RouteSelected = shadowRouteID()
			diag.BlockingReasons = []string{}
		} else {
			// Synthetic readiness proves the typed lifecycle, not a real macOS
			// Shadow route. Do not encode it as real-machine route evidence.
			diag.ShadowRouteStatus = "not_evaluated"
			diag.RoutesAttempted = []string{}
		}
		for _, scope := range diag.RequestedScopes {
			switch scope {
			case "database":
				if credential != nil && len(credential.CatalogEntries) > 0 {
					diag.DatabaseTargetStatus = "present"
					diag.DatabaseCoverageStatus = "complete"
					diag.TargetBindingStatus = "hmac_verified"
					if credential.DatabaseCredential != nil {
						diag.CandidateMode = credential.DatabaseCredential.Mode
					} else {
						diag.CandidateMode = "per_database_enc_key"
					}
				}
			case "media":
				if credential != nil && credential.ImageKeys != nil {
					diag.MediaCoverageStatus = "complete"
					if diag.TargetBindingStatus == "unknown" {
						diag.TargetBindingStatus = "path_verified"
					}
				}
			}
		}
	case result.ErrorCode == contract.ErrorProductionRouteDisabled:
		diag.ShadowRouteStatus = "unavailable_in_build"
		diag.RoutesAttempted = []string{}
		diag.BlockingReasons = []string{"shadow_route_unavailable_in_build"}
	}
	return diag
}

func disabledShadowResult(request contract.Request) contract.Result {
	return contract.Result{
		Version: contract.Version, RequestID: request.RequestID, Status: "failed",
		ErrorCode: contract.ErrorProductionRouteDisabled,
	}
}

func ExecuteShadow(ctx context.Context, request protocolmodel.AcquireRequest, runner ShadowRunner) (protocolmodel.Response, error) {
	if request.Workflow.Operation != "shadow" || request.Workflow.Shadow == nil {
		return protocolmodel.Response{}, errors.New("Shadow command lacks its independent request")
	}
	if _, _, err := shadowScopeSelection(request.Scopes); err != nil {
		return protocolmodel.Response{}, err
	}
	inner := *request.Workflow.Shadow
	var output shadowmodel.Output
	var err error
	if runner == nil {
		output.Result = disabledShadowResult(inner)
	} else if inner.Operation == "qualify" {
		output, err = runner.Qualify(ctx, inner)
	} else {
		output, err = runner.Execute(ctx, inner)
	}
	defer clearBytes(output.Credential)
	if err != nil {
		return protocolmodel.Response{}, err
	}
	if err := output.Result.Validate(); err != nil {
		return protocolmodel.Response{}, errors.New("Shadow runner returned an invalid result")
	}
	response := protocolmodel.Response{
		Protocol: request.Protocol, RequestID: request.RequestID,
		Diagnostics: shadowDiagnostics(request, output.Result, nil, runner != nil && inner.Operation == "execute"),
	}
	if output.Result.Status == "ready" {
		credential, decodeErr := decodeShadowCredential(output.Credential)
		if decodeErr == nil {
			decodeErr = validateShadowCredentialForScopes(request, credential)
		}
		if decodeErr != nil {
			failed := output.Result
			failed.Status = "failed"
			failed.ErrorCode = contract.ErrorCredentialInvalid
			failed.CredentialReleased = false
			response.Diagnostics = shadowDiagnostics(request, failed, nil, runner != nil && inner.Operation == "execute")
			return protocolmodel.EnforceSecretPolicy(response), nil
		}
		response.CatalogID = credential.CatalogID
		response.CatalogEntries = credential.CatalogEntries
		response.DatabaseKeys = credential.DatabaseKeys
		response.DatabaseProfiles = credential.DatabaseProfiles
		response.DatabaseCredential = credential.DatabaseCredential
		response.ImageKeys = credential.ImageKeys
		response.Profiles = credential.Profiles
		response.Diagnostics = shadowDiagnostics(request, output.Result, &credential, runner != nil && inner.Operation == "execute")
	}
	return protocolmodel.EnforceSecretPolicy(response), nil
}
