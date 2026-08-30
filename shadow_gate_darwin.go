//go:build darwin

package provider

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"

	shadowmodel "github.com/zanescope/v-local-key-provider/internal/shadow"
	clockmodel "github.com/zanescope/v-local-key-provider/internal/shadowclock"
	shadowproduction "github.com/zanescope/v-local-key-provider/internal/shadowproduction"
)

func cowGateID() (string, error) {
	payload := make([]byte, 16)
	if _, err := rand.Read(payload); err != nil {
		return "", err
	}
	return hex.EncodeToString(payload), nil
}

func runShadowGateCommand(arguments []string, writer io.Writer) (bool, int) {
	if len(arguments) != 2 || (arguments[1] != "__shadow-cow-qualify" && arguments[1] != "__shadow-transform-qualify") {
		return false, 0
	}
	version := "v-local-shadow-cow-gate/v1"
	if arguments[1] == "__shadow-transform-qualify" {
		version = "v-local-shadow-transformation-gate/v1"
	}
	prelaunch, _, err := productionPrelaunch()
	if err != nil {
		_ = json.NewEncoder(writer).Encode(shadowproduction.CoWGateSummary{
			Version: version, Status: "failed",
		})
		return true, 3
	}
	securityRoot, err := prelaunch.Workspace.PrepareSecurityRoot(prelaunch.Account)
	if err != nil || securityRoot != prelaunch.Account.SecurityRoot {
		return true, 3
	}
	journal, err := shadowmodel.NewFileJournal(prelaunch.Account.SecurityRoot)
	if err != nil {
		return true, 3
	}
	locker, err := shadowmodel.NewFileLocker(prelaunch.Account.SecurityRoot)
	if err != nil {
		return true, 3
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	base := shadowproduction.CoWGate{
		Prelaunch: prelaunch, Journal: journal, Locker: locker, Clock: clockmodel.System{}, NewID: cowGateID,
	}
	var summary shadowproduction.CoWGateSummary
	var runErr error
	if arguments[1] == "__shadow-transform-qualify" {
		summary, runErr = (shadowproduction.TransformationGate{CoWGate: base}).Run(ctx)
	} else {
		summary, runErr = base.Run(ctx)
	}
	if encodeErr := json.NewEncoder(writer).Encode(summary); encodeErr != nil {
		return true, 4
	}
	if runErr != nil {
		return true, 3
	}
	return true, 0
}
