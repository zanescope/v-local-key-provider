//go:build windows

package daemon

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// validateDirectorySecurity 独立验证 endpoint 目录的 owner 和 DACL，
// 不依赖调用方曾经正确运行 securePrivateDirectory。只有当前用户和 LocalSystem
// 可以拥有 allow ACE，且 DACL 必须禁止从父目录继承。
func validateDirectorySecurity(path string) error {
	descriptor, err := windows.GetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return errors.New("daemon endpoint parent security descriptor is unavailable")
	}
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.Equals(currentUser.User.Sid) {
		return errors.New("daemon endpoint parent owner does not match the current user")
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("daemon endpoint parent DACL must be protected")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return errors.New("daemon endpoint parent DACL is unavailable")
	}
	localSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	currentUserAllowed := false
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil {
			return errors.New("daemon endpoint parent DACL cannot be inspected")
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if sid.Equals(currentUser.User.Sid) {
				currentUserAllowed = true
				continue
			}
			if sid.Equals(localSystem) {
				continue
			}
			return errors.New("daemon endpoint parent grants access to another principal")
		default:
			return errors.New("daemon endpoint parent contains an unsupported allow rule")
		}
	}
	if !currentUserAllowed {
		return errors.New("daemon endpoint parent does not grant access to the current user")
	}
	return nil
}
