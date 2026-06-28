package vfs

import "bytes"

// maxProviderPathLen is Linux PATH_MAX.
const maxProviderPathLen = 4096

// validateProviderPath rejects absolute guest paths a provider must not be
// asked to serve: empty, relative, NUL bytes, empty components, or "..".
func validateProviderPath(path []byte) error {
	if len(path) == 0 {
		return Err(EINVAL)
	}
	if path[0] != '/' {
		return Err(EINVAL)
	}
	if len(path) > maxProviderPathLen {
		return Err(ENAMETOOLONG)
	}
	if bytes.IndexByte(path, 0) >= 0 {
		return Err(EINVAL)
	}
	if len(path) == 1 {
		return nil
	}
	for _, part := range bytes.Split(path[1:], []byte{'/'}) {
		if len(part) == 0 {
			return Err(EINVAL)
		}
		if bytes.Equal(part, []byte(".")) || bytes.Equal(part, []byte("..")) {
			return Err(EPERM)
		}
		if len(part) > maxReaddirNameLen {
			return Err(ENAMETOOLONG)
		}
	}
	return nil
}

// validateSymlinkTarget rejects symlink targets that could escape the mount
// subtree: NUL bytes, absolute paths, and ".." components.
func validateSymlinkTarget(target []byte) error {
	if bytes.IndexByte(target, 0) >= 0 {
		return Err(EINVAL)
	}
	if len(target) > maxSymlinkTarget {
		return Err(ENAMETOOLONG)
	}
	if len(target) > 0 && target[0] == '/' {
		return Err(EPERM)
	}
	for _, part := range bytes.Split(target, []byte{'/'}) {
		if bytes.Equal(part, []byte("..")) {
			return Err(EPERM)
		}
	}
	return nil
}

func validateProviderPathForRequest(r request) error {
	switch r.kind {
	case rGetAttr, rReadDir, rReadLink, rRead, rWrite, rCreate, rMkdir, rRemove,
		rSetAttr, rListXattr, rFlush, rFsync, rFsyncDir:
		return validateProviderPath(r.path)
	case rSetXattr, rGetXattr, rRemoveXattr:
		if err := validateProviderPath(r.path); err != nil {
			return err
		}
		return validateXattrName(r.name)
	case rRename:
		if err := validateProviderPath(r.from); err != nil {
			return err
		}
		return validateProviderPath(r.to)
	case rSymlink:
		if err := validateProviderPath(r.path); err != nil {
			return err
		}
		if err := validateSymlinkTarget(r.target); err != nil {
			return err
		}
		return nil
	case rGetAttrMany:
		for _, p := range r.paths {
			if err := validateProviderPath(p); err != nil {
				return err
			}
		}
		return nil
	case rStatFs:
		return nil
	default:
		return Err(EINVAL)
	}
}
