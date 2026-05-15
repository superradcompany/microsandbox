// Filesystem operations example for the microsandbox Go SDK.
//
// Exercises the SandboxFs API end-to-end: Write/Read, List, Stat,
// Mkdir/Remove/RemoveDir, Copy, Rename, Exists, CopyFromHost / CopyToHost,
// and the streaming ReadStream / WriteStream helpers.
//
// Build: from sdk/go, run
//
//	go run ./examples/filesystem
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if err := microsandbox.EnsureInstalled(ctx); err != nil {
		log.Fatalf("EnsureInstalled: %v", err)
	}

	name := fmt.Sprintf("go-sdk-fs-%d", time.Now().Unix())
	log.Printf("creating sandbox %q", name)

	sb, err := microsandbox.CreateSandbox(ctx, name, microsandbox.WithImage("alpine:3.19"))
	if err != nil {
		log.Fatalf("CreateSandbox: %v", err)
	}
	defer func() {
		stopCtx, c := context.WithTimeout(context.Background(), 30*time.Second)
		defer c()
		_, _ = sb.StopAndWait(stopCtx)
		_ = sb.Close()
		_ = microsandbox.RemoveSandbox(context.Background(), name)
	}()

	fs := sb.FS()

	// ----- Basic write + read -----
	if err := fs.WriteString(ctx, "/tmp/note.txt", "hello\n"); err != nil {
		log.Fatalf("WriteString: %v", err)
	}
	got, err := fs.ReadString(ctx, "/tmp/note.txt")
	if err != nil {
		log.Fatalf("ReadString: %v", err)
	}
	fmt.Printf("  read /tmp/note.txt -> %q\n", got)

	// ----- Mkdir + List + Stat -----
	if err := fs.Mkdir(ctx, "/tmp/work/data"); err != nil {
		log.Fatalf("Mkdir: %v", err)
	}
	if err := fs.WriteString(ctx, "/tmp/work/data/a.txt", "alpha"); err != nil {
		log.Fatalf("WriteString a: %v", err)
	}
	if err := fs.WriteString(ctx, "/tmp/work/data/b.txt", "beta"); err != nil {
		log.Fatalf("WriteString b: %v", err)
	}
	entries, err := fs.List(ctx, "/tmp/work/data")
	if err != nil {
		log.Fatalf("List: %v", err)
	}
	fmt.Printf("  /tmp/work/data has %d entries:\n", len(entries))
	for _, e := range entries {
		st, err := fs.Stat(ctx, e.Path)
		if err != nil {
			log.Fatalf("Stat %s: %v", e.Path, err)
		}
		fmt.Printf("    %s  kind=%s size=%d isDir=%v\n", e.Path, e.Kind, st.Size, st.IsDir)
	}

	// ----- Copy / Rename / Exists / Remove -----
	if err := fs.Copy(ctx, "/tmp/work/data/a.txt", "/tmp/work/data/a.copy"); err != nil {
		log.Fatalf("Copy: %v", err)
	}
	if err := fs.Rename(ctx, "/tmp/work/data/b.txt", "/tmp/work/data/b.renamed"); err != nil {
		log.Fatalf("Rename: %v", err)
	}
	for _, p := range []string{
		"/tmp/work/data/a.copy",
		"/tmp/work/data/b.renamed",
		"/tmp/work/data/b.txt",
	} {
		ok, err := fs.Exists(ctx, p)
		if err != nil {
			log.Fatalf("Exists %s: %v", p, err)
		}
		fmt.Printf("  exists %s -> %v\n", p, ok)
	}
	if err := fs.Remove(ctx, "/tmp/work/data/a.copy"); err != nil {
		log.Fatalf("Remove single: %v", err)
	}
	if err := fs.RemoveDir(ctx, "/tmp/work"); err != nil {
		log.Fatalf("RemoveDir recursive: %v", err)
	}
	fmt.Println("  cleaned up /tmp/work")

	// ----- Host <-> guest transfer -----
	hostDir, err := os.MkdirTemp("", "go-sdk-fs-")
	if err != nil {
		log.Fatalf("TempDir: %v", err)
	}
	defer os.RemoveAll(hostDir)

	hostSrc := filepath.Join(hostDir, "from-host.txt")
	hostDst := filepath.Join(hostDir, "back-to-host.txt")
	const transfer = "round-tripped through a microVM"
	if err := os.WriteFile(hostSrc, []byte(transfer), 0o644); err != nil {
		log.Fatalf("WriteFile host: %v", err)
	}
	if err := fs.CopyFromHost(ctx, hostSrc, "/tmp/from-host.txt"); err != nil {
		log.Fatalf("CopyFromHost: %v", err)
	}
	if err := fs.CopyToHost(ctx, "/tmp/from-host.txt", hostDst); err != nil {
		log.Fatalf("CopyToHost: %v", err)
	}
	roundtrip, err := os.ReadFile(hostDst)
	if err != nil {
		log.Fatalf("ReadFile: %v", err)
	}
	if string(roundtrip) != transfer {
		log.Fatalf("roundtrip mismatch: got %q want %q", roundtrip, transfer)
	}
	fmt.Printf("  host -> guest -> host roundtrip OK (%d bytes)\n", len(roundtrip))

	// ----- Streaming read of a moderately large file -----
	if _, err := sb.Shell(ctx,
		"dd if=/dev/urandom of=/tmp/big.bin bs=1M count=2 status=none",
		microsandbox.WithExecTimeout(30*time.Second),
	); err != nil {
		log.Fatalf("dd: %v", err)
	}
	stream, err := fs.ReadStream(ctx, "/tmp/big.bin")
	if err != nil {
		log.Fatalf("ReadStream: %v", err)
	}
	var total int64
	for {
		chunk, err := stream.Recv(ctx)
		if err != nil {
			log.Fatalf("Recv: %v", err)
		}
		if chunk == nil {
			break
		}
		total += int64(len(chunk))
	}
	if err := stream.Close(); err != nil {
		log.Fatalf("ReadStream Close: %v", err)
	}
	fmt.Printf("  streaming read drained %d MiB (%d bytes)\n", total>>20, total)

	// ----- Streaming write -----
	wstream, err := fs.WriteStream(ctx, "/tmp/composed.txt")
	if err != nil {
		log.Fatalf("WriteStream: %v", err)
	}
	for _, chunk := range []string{"alpha;", "beta;", "gamma;"} {
		if _, err := wstream.Write([]byte(chunk)); err != nil {
			log.Fatalf("WriteStream Write: %v", err)
		}
	}
	if err := wstream.Close(ctx); err != nil {
		log.Fatalf("WriteStream Close: %v", err)
	}
	composed, err := fs.ReadString(ctx, "/tmp/composed.txt")
	if err != nil {
		log.Fatalf("ReadString composed: %v", err)
	}
	fmt.Printf("  streaming write composed -> %q\n", composed)

	// ----- io.WriterTo: pump into stdout via the read stream -----
	if err := fs.WriteString(ctx, "/tmp/payload.txt", "via WriterTo\n"); err != nil {
		log.Fatalf("Write payload: %v", err)
	}
	rs, err := fs.ReadStream(ctx, "/tmp/payload.txt")
	if err != nil {
		log.Fatalf("ReadStream: %v", err)
	}
	var sink strings.Builder
	if _, err := rs.WriteTo(&sink); err != nil {
		log.Fatalf("WriteTo: %v", err)
	}
	_ = rs.Close()
	fmt.Printf("  WriterTo drained -> %q\n", sink.String())

	// Sanity discard so the io import is always live.
	_, _ = io.Copy(io.Discard, strings.NewReader(""))

	fmt.Println("OK — filesystem example passed")
}
