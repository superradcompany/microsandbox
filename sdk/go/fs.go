package microsandbox

import (
	"context"
	"time"
)

// SandboxFs provides filesystem operations on a running sandbox. Obtain
// via Sandbox.FS.
type SandboxFs struct {
	sandbox *Sandbox
}

// FsEntry is a single directory listing entry.
type FsEntry struct {
	Path string
	Kind string // "file" | "dir" | "symlink" | "other"
	Size int64
	Mode uint32
}

// FsStat is file metadata.
type FsStat struct {
	Path    string
	Size    int64
	Mode    uint32
	ModTime time.Time // zero-valued if the guest did not report a timestamp
	IsDir   bool
}

// Read reads the contents of a file from the sandbox.
func (fs *SandboxFs) Read(ctx context.Context, path string) ([]byte, error) {
	data, err := fs.sandbox.inner.FsRead(ctx, path)
	return data, wrapFFI(err)
}

// ReadString reads a file and returns its contents as a string.
func (fs *SandboxFs) ReadString(ctx context.Context, path string) (string, error) {
	data, err := fs.Read(ctx, path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Write writes data to a file in the sandbox, creating or truncating it.
func (fs *SandboxFs) Write(ctx context.Context, path string, data []byte) error {
	return wrapFFI(fs.sandbox.inner.FsWrite(ctx, path, data))
}

// WriteString writes a string to a file in the sandbox.
func (fs *SandboxFs) WriteString(ctx context.Context, path, content string) error {
	return fs.Write(ctx, path, []byte(content))
}

// List lists the entries in a directory in the sandbox.
func (fs *SandboxFs) List(ctx context.Context, path string) ([]FsEntry, error) {
	raw, err := fs.sandbox.inner.FsList(ctx, path)
	if err != nil {
		return nil, wrapFFI(err)
	}
	entries := make([]FsEntry, len(raw))
	for i, e := range raw {
		entries[i] = FsEntry{Path: e.Path, Kind: e.Kind, Size: e.Size, Mode: e.Mode}
	}
	return entries, nil
}

// Stat returns metadata for a file or directory.
func (fs *SandboxFs) Stat(ctx context.Context, path string) (*FsStat, error) {
	raw, err := fs.sandbox.inner.FsStat(ctx, path)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &FsStat{
		Path:    path,
		Size:    raw.Size,
		Mode:    raw.Mode,
		ModTime: raw.ModTime(),
		IsDir:   raw.IsDir(),
	}, nil
}

// CopyFromHost copies a host file into the sandbox.
func (fs *SandboxFs) CopyFromHost(ctx context.Context, hostPath, guestPath string) error {
	return wrapFFI(fs.sandbox.inner.FsCopyFromHost(ctx, hostPath, guestPath))
}

// CopyToHost copies a sandbox file to the host.
func (fs *SandboxFs) CopyToHost(ctx context.Context, guestPath, hostPath string) error {
	return wrapFFI(fs.sandbox.inner.FsCopyToHost(ctx, guestPath, hostPath))
}
