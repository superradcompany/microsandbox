package vfs

import "bytes"

// maxReaddirNameLen is Linux NAME_MAX.
const maxReaddirNameLen = 255

// filteredReaddirNameLog is invoked when a provider returns a readdir name that
// fails validation and is dropped. Defaults to a no-op; see
// SetFilteredReaddirNameLog.
var filteredReaddirNameLog func(name []byte)

// filteredReaddirKindLog is invoked when a provider returns a readdir entry kind
// the wire cannot represent and the entry is dropped. Defaults to a no-op; see
// SetFilteredReaddirKindLog.
var filteredReaddirKindLog func(kind NodeKind)

// SetFilteredReaddirNameLog installs a callback for invalid readdir names that
// are dropped during pagination. Passing nil restores the default no-op.
func SetFilteredReaddirNameLog(fn func(name []byte)) {
	filteredReaddirNameLog = fn
}

// SetFilteredReaddirKindLog installs a callback for invalid readdir entry kinds
// that are dropped during pagination. Passing nil restores the default no-op.
func SetFilteredReaddirKindLog(fn func(kind NodeKind)) {
	filteredReaddirKindLog = fn
}

func logFilteredReaddirName(name []byte) {
	if filteredReaddirNameLog != nil {
		filteredReaddirNameLog(name)
	}
}

func logFilteredReaddirKind(kind NodeKind) {
	if filteredReaddirKindLog != nil {
		filteredReaddirKindLog(kind)
	}
}

func checkDirEmptyForRmdir(entries []DirEntry) error {
	visible := 0
	hasInvalid := false
	for _, entry := range entries {
		if bytes.Equal(entry.Name, []byte(".")) || bytes.Equal(entry.Name, []byte("..")) {
			continue
		}
		if validateReaddirName(entry.Name) != nil {
			hasInvalid = true
			continue
		}
		visible++
	}
	if visible > 0 {
		return Err(ENOTEMPTY)
	}
	if hasInvalid {
		return Err(EIO)
	}
	return nil
}

// validateReaddirName rejects directory entry names a provider must not return.
// The runtime scaffold synthesizes "." and ".." itself.
func validateReaddirName(name []byte) error {
	if len(name) == 0 {
		return Err(EINVAL)
	}
	if bytes.IndexByte(name, 0) >= 0 {
		return Err(EINVAL)
	}
	if bytes.Equal(name, []byte(".")) || bytes.Equal(name, []byte("..")) {
		return Err(EPERM)
	}
	if bytes.IndexByte(name, '/') >= 0 {
		return Err(EPERM)
	}
	if len(name) > maxReaddirNameLen {
		return Err(ENAMETOOLONG)
	}
	return nil
}

// validateXattrName rejects extended-attribute names a provider must not be asked
// to serve: empty, NUL bytes, `/`, or longer than Linux NAME_MAX.
func validateXattrName(name []byte) error {
	if len(name) == 0 {
		return Err(EINVAL)
	}
	if bytes.IndexByte(name, 0) >= 0 {
		return Err(EINVAL)
	}
	if bytes.IndexByte(name, '/') >= 0 {
		return Err(EINVAL)
	}
	if len(name) > maxReaddirNameLen {
		return Err(ENAMETOOLONG)
	}
	return nil
}
