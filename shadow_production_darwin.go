//go:build darwin

package provider

import (
	"errors"
	"os"
	"path/filepath"

	commandmodel "github.com/zanescope/v-local-key-provider/internal/command"
	shadowaccount "github.com/zanescope/v-local-key-provider/internal/shadowaccount"
	shadowproduction "github.com/zanescope/v-local-key-provider/internal/shadowproduction"
	shadowsource "github.com/zanescope/v-local-key-provider/internal/shadowsource"
	shadowworkspace "github.com/zanescope/v-local-key-provider/internal/shadowworkspace"
)

func productionPrelaunch() (*shadowproduction.Prelaunch, string, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, "", err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil || filepath.Base(executable) != "v-local-key-provider" {
		return nil, "", errors.New("Provider is not running from a frozen production build set")
	}
	bundle, err := shadowproduction.LoadBundle(filepath.Dir(executable))
	if err != nil {
		return nil, "", err
	}
	account, err := shadowaccount.ResolveCurrent()
	if err != nil {
		return nil, "", err
	}
	prelaunch, err := shadowproduction.NewPrelaunch(
		bundle, account, "/Applications/WeChat.app", shadowsource.Inspector{}, shadowworkspace.New(),
		defaultSecurityPostureStatus,
	)
	if err != nil {
		return nil, "", err
	}
	return prelaunch, bundle.Digest, nil
}

func productionQualificationRunner() (commandmodel.ShadowRunner, string) {
	prelaunch, digest, err := productionPrelaunch()
	if err != nil {
		return nil, ""
	}
	return shadowproduction.QualificationRunner{Prelaunch: prelaunch}, digest
}
