package microsandbox

import (
	"context"
	"io"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// SandboxFs provides filesystem operations on a running sandbox. Obtain
// via Sandbox.FS.
type SandboxFs struct {
	sandbox *Sandbox
}

// FsEntry is a single directory listing entry.
type FsEntry struct {
	Path string
	Kind FsEntryKind
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
		entries[i] = FsEntry{Path: e.Path, Kind: FsEntryKind(e.Kind), Size: e.Size, Mode: e.Mode}
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

// Mkdir creates a directory (and any missing parents) inside the sandbox.
func (fs *SandboxFs) Mkdir(ctx context.Context, path string) error {
	return wrapFFI(fs.sandbox.inner.FsMkdir(ctx, path))
}

// Remove deletes a single file. Use RemoveDir for directories.
func (fs *SandboxFs) Remove(ctx context.Context, path string) error {
	return wrapFFI(fs.sandbox.inner.FsRemove(ctx, path))
}

// RemoveDir removes a directory recursively.
func (fs *SandboxFs) RemoveDir(ctx context.Context, path string) error {
	return wrapFFI(fs.sandbox.inner.FsRemoveDir(ctx, path))
}

// Copy copies a file within the sandbox.
func (fs *SandboxFs) Copy(ctx context.Context, src, dst string) error {
	return wrapFFI(fs.sandbox.inner.FsCopy(ctx, src, dst))
}

// Rename renames (or moves) a file or directory within the sandbox.
func (fs *SandboxFs) Rename(ctx context.Context, src, dst string) error {
	return wrapFFI(fs.sandbox.inner.FsRename(ctx, src, dst))
}

// Exists reports whether a file or directory exists at the given path.
func (fs *SandboxFs) Exists(ctx context.Context, path string) (bool, error) {
	ok, err := fs.sandbox.inner.FsExists(ctx, path)
	if err != nil {
		return false, wrapFFI(err)
	}
	return ok, nil
}

// ---------------------------------------------------------------------------
// Streaming read
// ---------------------------------------------------------------------------

// FsReadStream is an open streaming read from a guest file. Obtain via
// SandboxFs.ReadStream. Must be closed with Close when done.
type FsReadStream struct {
	inner *ffi.FsReadStreamHandle
}

// Recv returns the next chunk of data. Returns nil, nil at EOF.
func (s *FsReadStream) Recv(ctx context.Context) ([]byte, error) {
	chunk, err := s.inner.Recv(ctx)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return chunk, nil
}

// WriteTo implements io.WriterTo: drains the stream into w, returning total
// bytes written. Closes the stream when done.
func (s *FsReadStream) WriteTo(w io.Writer) (int64, error) {
	var total int64
	ctx := context.Background()
	for {
		chunk, err := s.Recv(ctx)
		if err != nil {
			_ = s.Close()
			return total, err
		}
		if chunk == nil {
			break
		}
		n, err := w.Write(chunk)
		total += int64(n)
		if err != nil {
			_ = s.Close()
			return total, err
		}
	}
	return total, s.Close()
}

// Close releases the read stream handle.
func (s *FsReadStream) Close() error {
	return wrapFFI(s.inner.Close())
}

// ReadStream opens a streaming read from a guest file. The caller must close
// the returned FsReadStream when done.
func (fs *SandboxFs) ReadStream(ctx context.Context, path string) (*FsReadStream, error) {
	h, err := fs.sandbox.inner.FsReadStream(ctx, path)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &FsReadStream{inner: h}, nil
}

// ---------------------------------------------------------------------------
// Streaming write
// ---------------------------------------------------------------------------

// FsWriteStream is an open streaming write to a guest file. Obtain via
// SandboxFs.WriteStream. Must be closed with Close to finalise the write.
type FsWriteStream struct {
	inner *ffi.FsWriteStreamHandle
}

// Write sends a chunk of data to the guest file. Implements io.Writer.
func (s *FsWriteStream) Write(p []byte) (int, error) {
	if err := wrapFFI(s.inner.Write(context.Background(), p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

// WriteCtx sends a chunk of data with explicit context control.
func (s *FsWriteStream) WriteCtx(ctx context.Context, data []byte) error {
	return wrapFFI(s.inner.Write(ctx, data))
}

// Close finalises the write (sends EOF marker) and waits for the guest to
// confirm. Must be called to complete the write operation.
func (s *FsWriteStream) Close(ctx context.Context) error {
	return wrapFFI(s.inner.Close(ctx))
}

// WriteStream opens a streaming write to a guest file. The caller must call
// Close on the returned FsWriteStream to finalise the operation.
func (fs *SandboxFs) WriteStream(ctx context.Context, path string) (*FsWriteStream, error) {
	h, err := fs.sandbox.inner.FsWriteStream(ctx, path)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &FsWriteStream{inner: h}, nil
}
