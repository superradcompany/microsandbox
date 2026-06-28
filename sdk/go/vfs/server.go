package vfs

import (
	"bufio"
	"errors"
	"io"
	"sync"
	"sync/atomic"
)

// MaxConcurrentOps bounds how many provider calls may run at once per mount.
// Matches the expectation that PathFs implementations are concurrent-safe but
// should not be flooded without limit when the guest issues parallel I/O.
//
// Invariant: this must stay in sync with the requester-side MAX_PENDING_CALLS in
// crates/filesystem/lib/backends/vfs/rpc/transport.rs — the two bound the same
// in-flight window from opposite ends of the socket. Change both together.
const MaxConcurrentOps = 16

// ServeOption configures a [Serve] loop.
type ServeOption func(*serveOptions)

type serveOptions struct {
	// errorf reports a recovered provider panic. Defaults to a no-op; pass
	// [WithErrorLog] to route messages into your own logger.
	errorf func(format string, args ...any)
}

// WithErrorLog sets the function used to report a recovered provider panic and
// non-EOF serve-loop exit errors. A library should not write to the global
// logger unconditionally; pass this to route messages into your own logger
// (or a no-op to silence them).
func WithErrorLog(fn func(format string, args ...any)) ServeOption {
	return func(o *serveOptions) {
		if fn != nil {
			o.errorf = fn
		}
	}
}

// Serve runs the request/response loop for one virtual mount: it reads framed
// CBOR requests from conn, dispatches each to fs, and writes the framed CBOR
// reply. It returns nil on a clean EOF (the runtime closed the channel, e.g. on
// sandbox shutdown) and a non-nil error on an I/O failure.
//
// Requests are dispatched concurrently up to [MaxConcurrentOps]; the read
// loop acquires a slot before decoding each frame so goroutine count stays
// bounded under load. Replies are serialized on the wire.
func Serve(conn io.ReadWriter, fs PathFs, opts ...ServeOption) error {
	o := serveOptions{errorf: func(string, ...any) {}}
	for _, opt := range opts {
		opt(&o)
	}
	// Responder half of the hello handshake: read the peer's hello and validate
	// the protocol version, then send ours. A version skew fails here — loudly —
	// before any ops flow. A clean EOF before the handshake is a no-op close.
	if _, err := readHello(conn); err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}
	if err := writeHello(conn); err != nil {
		return err
	}

	var writeMu sync.Mutex
	// One buffered writer for the whole connection, reused under writeMu rather
	// than reallocated per response on the hot path.
	bw := bufio.NewWriter(conn)
	// One buffered reader for the read loop (single-threaded), so each frame's
	// length/id/body reads coalesce instead of costing three syscalls apiece.
	br := bufio.NewReader(conn)
	var readDirCache readDirCache
	var shutdown sync.Once
	var aborted atomic.Bool
	abort := func() {
		shutdown.Do(func() {
			aborted.Store(true)
			if c, ok := conn.(io.Closer); ok {
				_ = c.Close()
			}
		})
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, MaxConcurrentOps)
	shutdownWorkers := func() {
		if !waitGroupWithTimeout(&wg, virtualMountServeShutdownWait) {
			o.errorf("vfs: timed out waiting for in-flight provider calls during shutdown")
			abort()
		}
	}
	defer shutdownWorkers()

	for {
		if aborted.Load() {
			return nil
		}
		// Bound in-flight work before reading the next frame so a fast guest
		// cannot queue unbounded goroutines parked on the semaphore. This
		// matches the requester-side MAX_PENDING_CALLS window from the runtime.
		sem <- struct{}{}
		id, reqBytes, err := readFrame(br)
		if err != nil {
			<-sem
			if err == io.EOF {
				return nil
			}
			o.errorf("vfs: serve loop ended: %v", err)
			return err
		}

		wg.Add(1)
		go func(id uint64, reqBytes []byte) {
			defer func() {
				<-sem
				wg.Done()
			}()
			var resp response
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						o.errorf("vfs: provider panic: %v", rec)
						resp = response{kind: pErr, errno: EIO}
					}
				}()
				if req, derr := decodeRequest(reqBytes); derr != nil {
					errno := EINVAL
					var eno *Errno
					if errors.As(derr, &eno) {
						errno = eno.Code
					}
					resp = response{kind: pErr, errno: int32(errno)}
				} else {
					resp = dispatch(fs, req, &readDirCache)
				}
			}()
			// Encode into a pooled buffer so steady-state replies don't each
			// allocate a fresh one. writeFrame copies the payload into bw before
			// returning, so the buffer is safe to recycle immediately after.
			enc := getEncoder()
			appendResponse(enc, resp)
			if len(enc.buf) > maxFrameLen {
				o.errorf("vfs: response exceeds frame limit (%d > %d)", len(enc.buf), maxFrameLen)
				putEncoder(enc)
				enc = getEncoder()
				appendResponse(enc, response{kind: pErr, errno: EIO})
			}
			writeMu.Lock()
			// writeFrame flushes bw itself (via flushWriter), so the framed
			// reply is on the wire before the lock is released.
			werr := writeFrame(bw, id, enc.buf)
			writeMu.Unlock()
			putEncoder(enc)
			if werr != nil {
				abort()
			}
		}(id, reqBytes)
	}
}
