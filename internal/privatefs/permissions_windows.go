package privatefs

import (
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func currentSID() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String(), nil
}

// RequirePrivateDirectory rejects shared Windows directories before a library
// can create sensitive sidecars with inherited access. It never rewrites parents.
func RequirePrivateDirectory(path string) error { return Check(path) }

// MkdirAll creates only missing directories with a private, inheritable DACL.
// Existing parents are not modified; callers validate their selected directory.
func MkdirAll(path string) error {
	info, err := os.Stat(path)
	if err == nil {
		if !info.IsDir() {
			return errors.New("private directory path is not a directory")
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	parent := filepath.Dir(path)
	if parent == path {
		return err
	}
	if err := MkdirAll(parent); err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	descriptor, err := privateDescriptor("OICI")
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	err = windows.CreateDirectory(name, &attributes)
	if err == windows.ERROR_ALREADY_EXISTS {
		return RequirePrivateDirectory(path)
	}
	return err
}

func privateDescriptor(flags string) (*windows.SECURITY_DESCRIPTOR, error) {
	sid, err := currentSID()
	if err != nil {
		return nil, err
	}
	return windows.SecurityDescriptorFromString("D:P(A;" + flags + ";FA;;;SY)(A;" + flags + ";FA;;;BA)(A;" + flags + ";FA;;;" + sid + ")")
}

// Create sets its protected DACL atomically at creation, before secret data is
// written or another account could open the file through inherited access.
func Create(path string) (*os.File, error) {
	descriptor, err := privateDescriptor("")
	if err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "create private file", Path: path, Err: err}
	}
	return os.NewFile(uintptr(handle), path), nil
}

// Restrict disables inherited access and grants the running identity, SYSTEM and
// built-in Administrators access. No localized account names are used.
func Restrict(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("private path must not be a symbolic link")
	}
	flags := ""
	if info.IsDir() {
		flags = "OICI"
	}
	descriptor, err := privateDescriptor(flags)
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// Check rejects null/empty DACLs, unknown ACE forms and access granted to any
// principal except the running identity, SYSTEM or built-in Administrators.
func Check(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("private path must not be a symbolic link")
	}
	sid, err := currentSID()
	if err != nil {
		return err
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	if dacl == nil || dacl.AceCount == 0 {
		return errors.New("private path has no explicit access policy")
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("unsupported private-file access policy")
		}
		principal := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if principal != sid && principal != "S-1-5-18" && principal != "S-1-5-32-544" {
			return errors.New("private path grants access to an unauthorized principal")
		}
	}
	return nil
}
