//go:build windows

package provider

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func livePrivateConfigPath() (string, error) {
	localAppData, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DEFAULT)
	if err != nil || localAppData == "" {
		return "", errors.New("Windows LocalAppData is unavailable")
	}
	return filepath.Join(localAppData, "v-local", "live-regression-private", "config.json"), nil
}

func openWindowsLivePrivateObject(path string, directory bool) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	access := uint32(windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES)
	if !directory {
		access |= windows.GENERIC_READ
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(name, access, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return windows.InvalidHandle, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		_ = windows.CloseHandle(handle)
		return windows.InvalidHandle, err
	}
	attributes := info.FileAttributes
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		(directory && attributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0) ||
		(!directory && attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) {
		_ = windows.CloseHandle(handle)
		return windows.InvalidHandle, errors.New("live private object type is unsafe")
	}
	return handle, nil
}

func windowsLivePrivateACLIsExclusive(handle windows.Handle) bool {
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.IsValid() {
		return false
	}
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || currentUser == nil || currentUser.User.Sid == nil || !owner.Equals(currentUser.User.Sid) {
		return false
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return false
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		return false
	}
	userAllowed := false
	systemAllowed := false
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil ||
			ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			uintptr(ace.Header.AceSize) < unsafe.Offsetof(ace.SidStart)+unsafe.Sizeof(ace.SidStart) {
			return false
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() {
			return false
		}
		switch {
		case sid.Equals(currentUser.User.Sid):
			userAllowed = true
		case sid.Equals(system):
			systemAllowed = true
		default:
			return false
		}
	}
	return userAllowed && systemAllowed
}

func windowsLivePrivatePathIsPlainDirectory(path string) bool {
	handle, err := openWindowsLivePrivateObject(path, true)
	if err != nil {
		return false
	}
	_ = windows.CloseHandle(handle)
	return true
}

func readWindowsLivePrivateConfig(path string) ([]byte, error) {
	directory := filepath.Dir(path)
	directoryHandle, err := openWindowsLivePrivateObject(directory, true)
	if err != nil {
		return nil, err
	}
	directorySecure := windowsLivePrivateACLIsExclusive(directoryHandle)
	_ = windows.CloseHandle(directoryHandle)
	if !directorySecure {
		return nil, errors.New("live private config directory ACL is unsafe")
	}
	handle, err := openWindowsLivePrivateObject(path, false)
	if err != nil {
		return nil, err
	}
	if !windowsLivePrivateACLIsExclusive(handle) {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("live private config ACL is unsafe")
	}
	file := os.NewFile(uintptr(handle), "live-regression-private-config")
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("live private config handle is unavailable")
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, livePrivateConfigMaxBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > livePrivateConfigMaxBytes {
		return nil, errors.New("live private config cannot be read safely")
	}
	return payload, nil
}

func readLivePrivateConfig() ([]byte, error) {
	path, err := livePrivateConfigPath()
	if err != nil {
		return nil, err
	}
	root := filepath.Dir(filepath.Dir(path))
	if !windowsLivePrivatePathIsPlainDirectory(root) {
		return nil, errors.New("v-local private root is unavailable or redirected")
	}
	return readWindowsLivePrivateConfig(path)
}
