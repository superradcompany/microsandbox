package vfs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// Linux errno values. A [PathFs] runs on the host (which may be macOS), but its
// errors are delivered to the *guest*, which is always Linux — so providers
// must use these constants (via [Err]) rather than the host's `syscall.Errno`,
// whose values differ across platforms (e.g. ENOSYS is 38 on Linux, 78 on
// macOS).
const (
	EPERM        = 1
	ENOENT       = 2
	EIO          = 5
	EBADF        = 9
	EAGAIN       = 11
	ENOMEM       = 12
	EACCES       = 13
	EBUSY        = 16
	EEXIST       = 17
	ENOTDIR      = 20
	EISDIR       = 21
	EINVAL       = 22
	EFBIG        = 27
	ENOSPC       = 28
	EROFS        = 30
	ERANGE       = 34
	ENAMETOOLONG = 36
	ENOSYS       = 38
	ENOTEMPTY    = 39
	ENODATA      = 61
	ENOTSUP      = 95
)

// Errno is an error carrying a Linux errno that propagates to the guest.
type Errno struct {
	// Code is a Linux errno value (see the constants in this package).
	Code int
}

func (e *Errno) Error() string {
	return fmt.Sprintf("vfs: errno %d", e.Code)
}

// Err wraps a Linux errno as an [error]. Use it from a [PathFs] method, e.g.
// `return vfs.Err(vfs.ENOENT)`.
func Err(code int) error {
	return &Errno{Code: code}
}

// errnoOf extracts the Linux errno an error should map to. A nil error is 0; an
// [Errno] (possibly wrapped via fmt.Errorf("...: %w", ...)) yields its code;
// common [os] / [fs] errors are translated when recognized; anything else falls
// back to [EIO].
func errnoOf(err error) int {
	if err == nil {
		return 0
	}
	var e *Errno
	if errors.As(err, &e) && e != nil {
		return e.Code
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return ENOENT
	case errors.Is(err, fs.ErrPermission):
		return EACCES
	case errors.Is(err, fs.ErrExist):
		return EEXIST
	case errors.Is(err, fs.ErrInvalid):
		return EINVAL
	case errors.Is(err, os.ErrDeadlineExceeded):
		return EAGAIN
	}
	return EIO
}
