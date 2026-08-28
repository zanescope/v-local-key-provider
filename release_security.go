package provider

import (
	"errors"
	"path/filepath"
	"strings"
)

// buildMode 会由每次签名 release 构建注入为 "release"。保留默认 development 值，可让
// 源码构建和协议 fixture 继续可用，同时不削弱签名发行件。
var buildMode = "development"

// releaseSignerSHA256 在签名前注入 Windows release 二进制。运行时 Authenticode 验证
// 必须匹配这张确切的叶证书，而非仅匹配当前机器信任的任意证书。
var releaseSignerSHA256 string

// releasePromotionSHA256 是经签名 release 构建器验证的外部 promotion manifest 内容摘要。
// 该 manifest 有意不编译进真机测试候选：它把候选与其内容寻址的真机证据绑定，同时避免
// 形成 binary/evidence hash 循环。
var releasePromotionSHA256 string

func releaseBuild() bool {
	return strings.EqualFold(strings.TrimSpace(buildMode), "release")
}

// knownBuildMode 限定构建身份的取值集合。运行时信任校验的宽松分支是
// `if !releaseBuild()`，因此任何无法识别的取值都会被当成开发构建放行。把未知取值挡在
// 入口，可以让「构建身份没有被正确注入」变成启动失败，而不是静默降级的信任策略。
func knownBuildMode(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "development", "candidate", "release":
		return true
	}
	return false
}

func releasePromotionReady() bool {
	return validWindowsSHA256(releasePromotionSHA256)
}

func validateReleaseCompatibilityRegistry(platform, architecture string, windowsEntries []windowsCompatibilityEntry, darwinEntries []darwinCompatibilityEntry) error {
	switch platform {
	case "windows":
		for _, entry := range windowsEntries {
			if entry.ProcessArchitecture == architecture && windowsRegistryEntryEligible(entry) {
				return nil
			}
		}
	case "darwin":
		for _, entry := range darwinEntries {
			if entry.ProcessArchitecture == architecture && darwinRegistryEntryEligible(entry) {
				return nil
			}
		}
	default:
		return errors.New("release compatibility target is unsupported")
	}
	return errors.New("release compatibility registry has no complete candidate entry for target")
}

func releaseCompatibilityReadiness(platform, architecture string) error {
	return validateReleaseCompatibilityRegistry(
		strings.ToLower(strings.TrimSpace(platform)), strings.ToLower(strings.TrimSpace(architecture)),
		windowsCompatibilityRegistry, darwinCompatibilityRegistry,
	)
}

func runtimeRole() string {
	arguments := processArguments()
	if len(arguments) < 2 {
		return "provider"
	}
	switch arguments[1] {
	case "helper-acquire", "helper-acquire-loopback":
		return "helper"
	case "internal-hook-watchdog":
		name := strings.TrimSuffix(strings.ToLower(filepath.Base(arguments[0])), ".exe")
		if name == "v-local-key-provider-helper" {
			return "helper"
		}
	case "daemon":
		if len(arguments) >= 3 && arguments[2] == "serve-helper" {
			return "helper"
		}
	}
	return "provider"
}

var processArguments = func() []string { return processArgs() }
