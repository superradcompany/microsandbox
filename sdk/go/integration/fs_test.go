//go:build integration && microsandbox_ffi_path

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

// TestFsMkdirCreatesParents verifies Mkdir creates intermediate directories.
func TestFsMkdirCreatesParents(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)
	fs := sb.FS()

	if err := fs.Mkdir(ctx, "/tmp/a/b/c"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	stat, err := fs.Stat(ctx, "/tmp/a/b/c")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !stat.IsDir {
		t.Error("Stat: not a directory")
	}
}

// TestFsCopy verifies a guest-side copy.
func TestFsCopy(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)
	fs := sb.FS()

	if err := fs.WriteString(ctx, "/tmp/copy-src.txt", "copy-content"); err != nil {
		t.Fatalf("Write src: %v", err)
	}
	if err := fs.Copy(ctx, "/tmp/copy-src.txt", "/tmp/copy-dst.txt"); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	dst, err := fs.ReadString(ctx, "/tmp/copy-dst.txt")
	if err != nil {
		t.Fatalf("Read dst: %v", err)
	}
	if dst != "copy-content" {
		t.Errorf("dst content: got %q", dst)
	}
}

// TestFsRename verifies a guest-side rename.
func TestFsRename(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)
	fs := sb.FS()

	if err := fs.WriteString(ctx, "/tmp/rename-src.txt", "rename-content"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := fs.Rename(ctx, "/tmp/rename-src.txt", "/tmp/rename-dst.txt"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if _, err := fs.Stat(ctx, "/tmp/rename-src.txt"); err == nil {
		t.Error("source still exists after Rename")
	}
	got, err := fs.ReadString(ctx, "/tmp/rename-dst.txt")
	if err != nil {
		t.Fatalf("Read dst: %v", err)
	}
	if got != "rename-content" {
		t.Errorf("dst content: got %q", got)
	}
}

// TestFsRemoveSingleFileAndRemoveDirRecursive covers both deletion
// helpers in one go.
func TestFsRemoveSingleFileAndRemoveDirRecursive(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)
	fs := sb.FS()

	if err := fs.Mkdir(ctx, "/tmp/rmme/sub"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := fs.WriteString(ctx, "/tmp/rmme/sub/file.txt", "x"); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Remove (single file).
	if err := fs.Remove(ctx, "/tmp/rmme/sub/file.txt"); err != nil {
		t.Fatalf("Remove file: %v", err)
	}
	if ok, _ := fs.Exists(ctx, "/tmp/rmme/sub/file.txt"); ok {
		t.Error("file still exists after Remove")
	}

	// RemoveDir (recursive).
	if err := fs.RemoveDir(ctx, "/tmp/rmme"); err != nil {
		t.Fatalf("RemoveDir: %v", err)
	}
	if ok, _ := fs.Exists(ctx, "/tmp/rmme"); ok {
		t.Error("dir still exists after RemoveDir")
	}
}

// TestFsExistsTrueAndFalse verifies both branches of Exists.
func TestFsExistsTrueAndFalse(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)
	fs := sb.FS()

	if err := fs.WriteString(ctx, "/tmp/exists.txt", "x"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	ok, err := fs.Exists(ctx, "/tmp/exists.txt")
	if err != nil || !ok {
		t.Errorf("Exists(written) = ok=%v err=%v", ok, err)
	}
	ok, err = fs.Exists(ctx, "/tmp/never-existed.txt")
	if err != nil {
		t.Fatalf("Exists(missing): err %v", err)
	}
	if ok {
		t.Error("Exists(missing): true")
	}
}

// TestFsCopyFromHostAndCopyToHost verifies a roundtrip via host-side files.
func TestFsCopyFromHostAndCopyToHost(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)
	fs := sb.FS()

	dir := t.TempDir()
	hostSrc := filepath.Join(dir, "src.txt")
	hostDst := filepath.Join(dir, "dst.txt")
	const content = "host->guest->host roundtrip"
	if err := os.WriteFile(hostSrc, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile host src: %v", err)
	}

	if err := fs.CopyFromHost(ctx, hostSrc, "/tmp/from-host.txt"); err != nil {
		t.Fatalf("CopyFromHost: %v", err)
	}
	got, err := fs.ReadString(ctx, "/tmp/from-host.txt")
	if err != nil {
		t.Fatalf("Guest Read: %v", err)
	}
	if got != content {
		t.Errorf("guest content: got %q want %q", got, content)
	}

	if err := fs.CopyToHost(ctx, "/tmp/from-host.txt", hostDst); err != nil {
		t.Fatalf("CopyToHost: %v", err)
	}
	roundtrip, err := os.ReadFile(hostDst)
	if err != nil {
		t.Fatalf("ReadFile host dst: %v", err)
	}
	if string(roundtrip) != content {
		t.Errorf("host roundtrip: got %q want %q", roundtrip, content)
	}
}

// TestFsReadAutoFallbackOnLargeFile is the regression test for the
// 1-MiB-buffer ceiling. We seed a ~3 MiB file inside the guest and rely on
// SandboxFs.Read to silently fall back to streaming.
func TestFsReadAutoFallbackOnLargeFile(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)
	fs := sb.FS()

	// 3 MiB; well past the 1 MiB FFI buffer (and past the ~750 KiB
	// post-base64-inflation ceiling for single-shot reads).
	const size = 3 * 1024 * 1024
	if _, err := sb.Shell(ctx,
		"dd if=/dev/urandom of=/tmp/big.bin bs=1M count=3 status=none",
		microsandbox.WithExecTimeout(30*time.Second)); err != nil {
		t.Fatalf("dd: %v", err)
	}

	got, err := fs.Read(ctx, "/tmp/big.bin")
	if err != nil {
		t.Fatalf("Read large: %v", err)
	}
	if len(got) != size {
		t.Errorf("Read large: got %d bytes, want %d", len(got), size)
	}

	// Cross-check the SHA-256 against a guest-computed hash to be sure no
	// bytes were lost or duplicated in the stream-fallback path.
	hashOut, err := sb.Shell(ctx, "sha256sum /tmp/big.bin | awk '{print $1}'")
	if err != nil {
		t.Fatalf("sha256sum: %v", err)
	}
	guestHash := strings.TrimSpace(hashOut.Stdout())
	sum := sha256.Sum256(got)
	hostHash := hex.EncodeToString(sum[:])
	if guestHash != hostHash {
		t.Errorf("hash mismatch: guest=%s host=%s", guestHash, hostHash)
	}
}

// TestFsReadStreamCollect drains a guest file via the streaming API.
func TestFsReadStreamCollect(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)
	fs := sb.FS()

	const want = "stream-payload-marker"
	if err := fs.WriteString(ctx, "/tmp/stream.txt", want); err != nil {
		t.Fatalf("Write: %v", err)
	}
	stream, err := fs.ReadStream(ctx, "/tmp/stream.txt")
	if err != nil {
		t.Fatalf("ReadStream: %v", err)
	}
	defer stream.Close()

	var out bytes.Buffer
	for {
		chunk, err := stream.Recv(ctx)
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		if chunk == nil {
			break
		}
		out.Write(chunk)
	}
	if out.String() != want {
		t.Errorf("stream output: got %q want %q", out.String(), want)
	}
}

// TestFsReadStreamWriteToDoesNotAutoClose is the regression test for the
// io.WriterTo behaviour change: WriteTo must not close the receiver, so a
// subsequent Close() succeeds.
func TestFsReadStreamWriteToDoesNotAutoClose(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)
	fs := sb.FS()

	if err := fs.WriteString(ctx, "/tmp/wt.txt", "writeto-payload"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	stream, err := fs.ReadStream(ctx, "/tmp/wt.txt")
	if err != nil {
		t.Fatalf("ReadStream: %v", err)
	}

	var buf bytes.Buffer
	n, err := stream.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if int(n) != len("writeto-payload") {
		t.Errorf("WriteTo: wrote %d bytes, want %d", n, len("writeto-payload"))
	}
	if buf.String() != "writeto-payload" {
		t.Errorf("WriteTo content: got %q", buf.String())
	}

	// The stream should still be live — Close must succeed once.
	if err := stream.Close(); err != nil {
		t.Errorf("Close after WriteTo: %v", err)
	}
}

// TestFsReadStreamCopyToContextCancellation verifies CopyTo honours ctx
// cancellation and returns ctx.Err() promptly.
func TestFsReadStreamCopyToContextCancellation(t *testing.T) {
	sb := newTestSandbox(t)
	outerCtx := integrationCtx(t)
	fs := sb.FS()

	// Big enough that draining won't finish before we cancel.
	if _, err := sb.Shell(outerCtx,
		"dd if=/dev/urandom of=/tmp/cancel.bin bs=1M count=8 status=none",
		microsandbox.WithExecTimeout(30*time.Second)); err != nil {
		t.Fatalf("dd: %v", err)
	}
	stream, err := fs.ReadStream(outerCtx, "/tmp/cancel.bin")
	if err != nil {
		t.Fatalf("ReadStream: %v", err)
	}
	defer stream.Close()

	cancelCtx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := stream.CopyTo(cancelCtx, io.Discard)
		errc <- err
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("CopyTo: expected error after ctx cancel")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("CopyTo did not return after ctx cancel within 5s")
	}
}

// TestFsWriteStreamRoundtrip writes a multi-chunk file via FsWriteStream
// and verifies the guest sees all bytes.
func TestFsWriteStreamRoundtrip(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)
	fs := sb.FS()

	stream, err := fs.WriteStream(ctx, "/tmp/wstream.txt")
	if err != nil {
		t.Fatalf("WriteStream: %v", err)
	}
	chunks := []string{"part-one;", "part-two;", "part-three"}
	for _, c := range chunks {
		if _, err := stream.Write([]byte(c)); err != nil {
			t.Fatalf("Write chunk: %v", err)
		}
	}
	if err := stream.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got, err := fs.ReadString(ctx, "/tmp/wstream.txt")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	want := strings.Join(chunks, "")
	if got != want {
		t.Errorf("content: got %q want %q", got, want)
	}
}

// TestFsStatModTime verifies that Stat populates ModTime to a real
// timestamp (within a sane window).
func TestFsStatModTime(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)
	fs := sb.FS()

	if err := fs.WriteString(ctx, "/tmp/mtime.txt", "x"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	stat, err := fs.Stat(ctx, "/tmp/mtime.txt")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if stat.ModTime.IsZero() {
		t.Error("ModTime: zero — guest stat should populate it")
	}
	// Sanity bounds: not before 2020, not in the far future.
	if stat.ModTime.Year() < 2020 || stat.ModTime.Year() > time.Now().Year()+1 {
		t.Errorf("ModTime out of range: %v", stat.ModTime)
	}
}

// TestFsListEntryFields verifies that List entries carry path, kind and
// size for files vs directories.
func TestFsListEntryFields(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)
	fs := sb.FS()

	if err := fs.Mkdir(ctx, "/tmp/listed"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := fs.WriteString(ctx, "/tmp/listed/file.txt", "list me"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	entries, err := fs.List(ctx, "/tmp/listed")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var fileEntry *microsandbox.FsEntry
	for i := range entries {
		if strings.HasSuffix(entries[i].Path, "file.txt") {
			fileEntry = &entries[i]
		}
	}
	if fileEntry == nil {
		t.Fatalf("file.txt missing from listing: %v", entries)
	}
	if fileEntry.Kind != microsandbox.FsEntryKindFile {
		t.Errorf("Kind: got %q want %q", fileEntry.Kind, microsandbox.FsEntryKindFile)
	}
	if fileEntry.Size <= 0 {
		t.Errorf("Size: got %d", fileEntry.Size)
	}
}

// TestFsReadOnNonexistentReturnsTypedError verifies the error path: a
// missing file returns a typed *Error with kind=Filesystem (the runtime
// surfaces guest fs failures under that umbrella).
func TestFsReadOnNonexistentReturnsTypedError(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)
	fs := sb.FS()

	_, err := fs.Read(ctx, "/never-existed-go-sdk-test")
	if err == nil {
		t.Fatal("expected error reading missing file")
	}
	if !microsandbox.IsKind(err, microsandbox.ErrFilesystem) &&
		!microsandbox.IsKind(err, microsandbox.ErrPathNotFound) {
		t.Errorf("missing file: want ErrFilesystem/ErrPathNotFound, got %v", err)
	}
	// Confirm the unwrapped error actually carries a useful message.
	var typed *microsandbox.Error
	if !errors.As(err, &typed) {
		t.Fatalf("error not *microsandbox.Error: %T", err)
	}
	if typed.Message == "" {
		t.Error("Error.Message: empty")
	}
}
