// Package vfs lets a Go program implement a programmable filesystem and serve
// it into a microsandbox sandbox — the "filesystem is all you need" pattern.
//
// A user implements [PathFs] (answering operations addressed by absolute guest
// path) and runs [Serve] on the channel the SDK hands out for a virtual mount.
// The microsandbox runtime, in its own process, runs the FUSE scaffold and
// forwards each operation here as an RPC; this package decodes the request,
// dispatches it to the provider, and encodes the reply.
//
// This package is the parent-process (server) half of the bridge described in
// docs/sandboxes/virtual-filesystem.mdx. It is deliberately dependency-free.
package vfs

import "time"

// NodeKind is the type of a filesystem node. The byte values match the Rust
// scaffold's wire encoding.
type NodeKind uint8

const (
	// File is a regular file.
	File NodeKind = 0
	// Dir is a directory.
	Dir NodeKind = 1
	// Symlink is a symbolic link.
	Symlink NodeKind = 2
	// Char is a character device.
	Char NodeKind = 3
	// Block is a block device.
	Block NodeKind = 4
	// Fifo is a named pipe.
	Fifo NodeKind = 5
	// Socket is a Unix domain socket.
	Socket NodeKind = 6
)

// Attr is the portable attribute shape for a node. The runtime fills sensible
// defaults for zero-valued optional fields.
type Attr struct {
	// Kind is the node type; combined with Mode to form the full st_mode.
	Kind NodeKind
	// Mode is the permission bits (e.g. 0o644); type bits derive from Kind.
	Mode uint32
	// Size in bytes (0 for non-regular files).
	Size uint64
	// UID is the owner user id.
	UID uint32
	// GID is the owner group id.
	GID uint32
	// Nlink is the hard-link count; 0 lets the runtime default it (2 for
	// directories, 1 otherwise).
	Nlink uint64
	// Rdev is the device number for Char/Block nodes; ignored otherwise.
	Rdev uint32
	// Atime is the last-access time; the zero value means "current time".
	Atime time.Time
	// Mtime is the last-modification time; the zero value means "current time".
	Mtime time.Time
	// Ctime is the last status-change time; the zero value means "current time".
	Ctime time.Time
}

// DirEntry is one child returned by [PathFs.ReadDir]. The "." and ".." entries
// are synthesized by the runtime and must not be included.
type DirEntry struct {
	// Name is a single path component (no '/').
	Name []byte
	// Kind is the entry's node type.
	Kind NodeKind
}

// StatFs reports filesystem statistics. The zero value is a generic, unbounded
// volume once defaults are applied by the runtime.
type StatFs struct {
	// Bsize is the filesystem block size.
	Bsize uint64
	// Frsize is the fragment size.
	Frsize uint64
	// Blocks is the total number of data blocks.
	Blocks uint64
	// Bfree is the number of free blocks.
	Bfree uint64
	// Bavail is the number of free blocks available to unprivileged users.
	Bavail uint64
	// Files is the total number of inodes.
	Files uint64
	// Ffree is the number of free inodes.
	Ffree uint64
	// Namemax is the maximum filename length.
	Namemax uint64
}

// SetAttrValid is a bitset marking which fields of an [Attr] a [PathFs.SetAttr]
// call should apply. The bit values match the FUSE FATTR_* flags used by the
// Rust scaffold's SetattrValid.
type SetAttrValid uint32

const (
	// SetMode marks the Mode field valid.
	SetMode SetAttrValid = 1
	// SetUID marks the UID field valid.
	SetUID SetAttrValid = 2
	// SetGID marks the GID field valid.
	SetGID SetAttrValid = 4
	// SetSize marks the Size field valid.
	SetSize SetAttrValid = 8
	// SetAtime marks the Atime field valid.
	SetAtime SetAttrValid = 16
	// SetMtime marks the Mtime field valid.
	SetMtime SetAttrValid = 32
	// SetAtimeNow requests Atime be set to the current time.
	SetAtimeNow SetAttrValid = 128
	// SetMtimeNow requests Mtime be set to the current time.
	SetMtimeNow SetAttrValid = 256
	// SetCtime marks the Ctime field valid.
	SetCtime SetAttrValid = 1024
)

// Has reports whether flag is set.
func (v SetAttrValid) Has(flag SetAttrValid) bool {
	return v&flag != 0
}

// PathFs is a path-addressed filesystem backend. All paths are absolute and
// begin with '/'; the root is "/". Implementations must be safe for concurrent
// use. Methods report failure by returning an [*Errno] (via [Err]); any other
// non-nil error is surfaced to the guest as EIO.
//
// Embed [ReadOnly] to get ENOSYS defaults for every mutating method and a
// generic StatFs, then implement just GetAttr, ReadDir, and Read.
type PathFs interface {
	// GetAttr returns attributes for the node at path, or ENOENT if absent.
	GetAttr(path []byte) (Attr, error)
	// ReadDir lists the children of the directory at path (excluding ./..).
	ReadDir(path []byte) ([]DirEntry, error)
	// Read returns up to size bytes from path starting at offset. A short
	// (or empty) result signals end-of-file.
	Read(path []byte, offset uint64, size uint32) ([]byte, error)

	// Write writes data to path at offset, returning bytes accepted.
	Write(path []byte, offset uint64, data []byte) (int, error)
	// Create makes a node at path per attr.Kind, returning its attributes.
	Create(path []byte, attr Attr) (Attr, error)
	// Mkdir makes a directory at path with the given permission bits.
	Mkdir(path []byte, mode uint32) (Attr, error)
	// Remove deletes the file, link, special node, or empty directory at path.
	Remove(path []byte) error
	// Rename moves from to to.
	Rename(from, to []byte) error
	// SetAttr applies the fields of attr selected by valid, returning the
	// resulting attributes.
	SetAttr(path []byte, attr Attr, valid SetAttrValid) (Attr, error)
	// Symlink creates a symbolic link at path pointing to target.
	Symlink(path, target []byte) (Attr, error)
	// ReadLink returns the target of the symbolic link at path.
	ReadLink(path []byte) ([]byte, error)
	// SetXattr sets extended attribute name on path.
	SetXattr(path, name, value []byte, flags uint32) error
	// GetXattr gets extended attribute name from path.
	GetXattr(path, name []byte) ([]byte, error)
	// ListXattr lists the extended-attribute names on path.
	ListXattr(path []byte) ([][]byte, error)
	// RemoveXattr removes extended attribute name from path.
	RemoveXattr(path, name []byte) error
	// Flush commits buffered writes for the file at path.
	Flush(path []byte) error
	// Fsync syncs the file at path to stable storage.
	Fsync(path []byte, datasync bool) error
	// StatFs reports filesystem statistics.
	StatFs() (StatFs, error)
}

// Linux renameat2 flag bits carried on the VFS RPC Rename request.
const (
	RenameNoReplace uint32 = 1
	RenameExchange  uint32 = 2
)

// RenameFlagsAware is implemented by providers that enforce rename flags
// atomically (for example under their own lock). When absent, the Serve loop
// falls back to a best-effort GetAttr pre-check before Rename.
type RenameFlagsAware interface {
	PathFs
	RenameWithFlags(from, to []byte, flags uint32) error
}

// ReadOnly provides ENOSYS defaults for every mutating [PathFs] method (and an
// empty-but-valid StatFs). Embed it in a provider that only needs a readable
// tree:
//
//	type myFs struct{ vfs.ReadOnly }
//	func (myFs) GetAttr(p []byte) (vfs.Attr, error) { ... }
//	func (myFs) ReadDir(p []byte) ([]vfs.DirEntry, error) { ... }
//	func (myFs) Read(p []byte, off uint64, n uint32) ([]byte, error) { ... }
type ReadOnly struct{}

// Write returns ENOSYS.
func (ReadOnly) Write([]byte, uint64, []byte) (int, error) { return 0, Err(ENOSYS) }

// Create returns ENOSYS.
func (ReadOnly) Create([]byte, Attr) (Attr, error) { return Attr{}, Err(ENOSYS) }

// Mkdir returns ENOSYS.
func (ReadOnly) Mkdir([]byte, uint32) (Attr, error) { return Attr{}, Err(ENOSYS) }

// Remove returns ENOSYS.
func (ReadOnly) Remove([]byte) error { return Err(ENOSYS) }

// Rename returns ENOSYS.
func (ReadOnly) Rename([]byte, []byte) error { return Err(ENOSYS) }

// SetAttr returns ENOSYS.
func (ReadOnly) SetAttr([]byte, Attr, SetAttrValid) (Attr, error) { return Attr{}, Err(ENOSYS) }

// Symlink returns ENOSYS.
func (ReadOnly) Symlink([]byte, []byte) (Attr, error) { return Attr{}, Err(ENOSYS) }

// ReadLink returns ENOSYS.
func (ReadOnly) ReadLink([]byte) ([]byte, error) { return nil, Err(ENOSYS) }

// SetXattr returns ENOSYS.
func (ReadOnly) SetXattr([]byte, []byte, []byte, uint32) error { return Err(ENOSYS) }

// GetXattr returns ENODATA (no such attribute).
func (ReadOnly) GetXattr([]byte, []byte) ([]byte, error) { return nil, Err(ENODATA) }

// ListXattr returns an empty list.
func (ReadOnly) ListXattr([]byte) ([][]byte, error) { return nil, nil }

// RemoveXattr returns ENOSYS.
func (ReadOnly) RemoveXattr([]byte, []byte) error { return Err(ENOSYS) }

// Flush is a no-op for read-only providers.
func (ReadOnly) Flush([]byte) error { return nil }

// Fsync is a no-op for read-only providers.
func (ReadOnly) Fsync([]byte, bool) error { return nil }

// StatFs returns a generic, unbounded volume.
func (ReadOnly) StatFs() (StatFs, error) {
	return StatFs{Bsize: 4096, Frsize: 4096, Namemax: 255}, nil
}
