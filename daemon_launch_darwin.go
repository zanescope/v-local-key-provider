//go:build darwin

package provider

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// delegateAcquisitionDaemonToPlatformHelper 用已安装的配套辅助程序替换短生命周期的
// 启动器，使守护进程沿用与单次获取相同的可信进程访问路径。命令行中不会携带请求或
// 秘密，只会转发私有端点路径和启动器身份。修改 SIP 和管理员提权不属于第二阶段范围。
func delegateAcquisitionDaemonToPlatformHelper(endpointPath, clientPath string) (bool, error) {
	helper, trustStatus := darwinHelperExecutableWithStatus()
	if helper == "" {
		if trustStatus == "untrusted" {
			return true, errors.New("macOS acquisition daemon companion helper is not trusted")
		}
		return true, errors.New("macOS acquisition daemon requires the installed companion helper")
	}
	launcher, err := os.Executable()
	if err != nil {
		return true, err
	}
	launcher, err = filepathEvalCanonical(launcher)
	if err != nil {
		return true, err
	}
	// helper 在写入 endpoint 前，会把该 launcher 版本与自身嵌入版本核对，防止已签名但
	// 过期的配套程序为新安装的 Provider 提供服务。
	args := []string{helper, "daemon", "serve-helper", endpointPath, launcher, clientPath, version}
	return true, syscall.Exec(helper, args, darwinCleanEnvironment())
}

func filepathEvalCanonical(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	return filepath.Abs(resolved)
}
