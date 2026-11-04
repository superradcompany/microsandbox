//go:build tcp_native && microsandbox_ffi_path && !windows

package microsandbox

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

const tcpTestBound = 5 * time.Second

func tcpTestConn(t *testing.T) (*TCPConn, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), tcpTestBound)
	t.Cleanup(cancel)
	native, fd, err := ffi.TCPTestDial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := newTCPConn(native, fd, "127.0.0.1", 80)
	if err != nil {
		t.Fatal(err)
	}
	return conn, ctx
}

func tcpAwait(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(tcpTestBound):
		t.Fatal("TCP call did not end")
		return nil
	}
}

func TestTCPConnGuestResetEndsBlockedIO(t *testing.T) {
	for _, tc := range []struct {
		name  string
		event uint8
	}{
		{"guest-cancel-and-failure", ffi.TCPTestGuestReset},
		{"guest-socket-failure-without-cancel", ffi.TCPTestGuestFailureWithoutCancel},
		{"invalid-control", ffi.TCPTestUnexpectedControl},
		{"invalid-credit", ffi.TCPTestInvalidCredit},
		{"invalid-record", ffi.TCPTestInvalidRecord},
		{"agent-disconnect", ffi.TCPTestDisconnect},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, ctx := tcpTestConn(t)
			defer conn.Abort()
			read, write := make(chan error, 1), make(chan error, 1)
			go func() { _, err := conn.Read(make([]byte, 1)); read <- err }()
			go func() { _, err := conn.Write(make([]byte, 16<<20)); write <- err }()
			if err := conn.native.TestEvent(ctx, ffi.TCPTestWaitInput); err != nil {
				t.Fatalf("writer never filled guest credit: %v", err)
			}
			select {
			case err := <-write:
				t.Fatalf("write should wait beyond credit: %v", err)
			default:
			}
			select {
			case err := <-read:
				t.Fatalf("read should wait for guest output: %v", err)
			default:
			}
			if err := conn.native.TestEvent(ctx, tc.event); err != nil {
				t.Fatal(err)
			}
			if err := tcpAwait(t, read); err == nil || errors.Is(err, io.EOF) {
				t.Fatalf("failed output became clean EOF: %v", err)
			}
			if err := tcpAwait(t, write); err == nil {
				t.Fatal("failed guest did not end blocked Write")
			}
			closed := make(chan error, 1)
			go func() { closed <- conn.Abort() }()
			err := tcpAwait(t, closed)
			if tc.event != ffi.TCPTestDisconnect && err != nil {
				t.Fatalf("guest terminal cleanup: %v", err)
			}
			if tc.event == ffi.TCPTestDisconnect && !errors.Is(err, ErrTCPCleanupUnknown) {
				t.Fatalf("failed protocol cleanup: %v", err)
			}
			if err := conn.native.TestEvent(ctx, ffi.TCPTestWaitDisconnect); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTCPConnAbortInterruptsCloseAndReadCannotReportEOF(t *testing.T) {
	conn, ctx := tcpTestConn(t)
	defer conn.Abort()
	read, closed, aborted := make(chan error, 1), make(chan error, 1), make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 1)); read <- err }()
	go func() { closed <- conn.Close() }()
	// The guest received an ordered finish and is withholding its terminal reply. Close is waiting.
	if err := conn.native.TestEvent(ctx, ffi.TCPTestWaitFinish); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	go func() { aborted <- conn.Abort() }()
	_ = tcpAwait(t, closed)
	_ = tcpAwait(t, aborted)
	if time.Since(started) >= 2*time.Second {
		t.Fatal("Abort waited for Close's idle deadline")
	}
	if err := tcpAwait(t, read); err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("concurrent Close certified truncated output: %v", err)
	}
	if err := conn.native.TestEvent(ctx, ffi.TCPTestWaitCancel); err != nil {
		t.Fatal(err)
	}
	if err := conn.native.TestEvent(ctx, ffi.TCPTestWaitDisconnect); err != nil {
		t.Fatal(err)
	}
}

func TestTCPConnAbortAcknowledgesLateCredit(t *testing.T) {
	conn, ctx := tcpTestConn(t)
	if _, err := conn.Write([]byte("partial")); err != nil {
		t.Fatal(err)
	}
	if err := conn.Abort(); err != nil {
		t.Fatalf("late valid credit prevented cleanup: %v", err)
	}
	if err := conn.native.TestEvent(ctx, ffi.TCPTestWaitCancel); err != nil {
		t.Fatal(err)
	}
	if err := conn.native.TestEvent(ctx, ffi.TCPTestWaitDisconnect); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.native.Status(); err == nil {
		t.Fatal("Abort leaked a native handle")
	}
}

func orphanTCPConn(t *testing.T) (*ffi.TCPConn, context.Context) {
	t.Helper()
	conn, ctx := tcpTestConn(t)
	if _, err := conn.Write([]byte("unfinished")); err != nil {
		t.Fatal(err)
	}
	native := conn.native
	runtime.KeepAlive(conn)
	return native, ctx
}

func TestTCPConnFinalizerAbortsUnfinishedStream(t *testing.T) {
	native, ctx := orphanTCPConn(t)
	runtime.GC()
	if err := native.TestEvent(ctx, ffi.TCPTestWaitCancel); err != nil {
		t.Fatalf("finalizer did not abort guest stream: %v", err)
	}
	if err := native.TestEvent(ctx, ffi.TCPTestWaitDisconnect); err != nil {
		t.Fatalf("finalizer relay did not end: %v", err)
	}
}

func TestTCPConnGuestResetDoesNotHangClose(t *testing.T) {
	conn, ctx := tcpTestConn(t)
	if err := conn.native.TestEvent(ctx, ffi.TCPTestGuestReset); err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- conn.Close() }()
	_ = tcpAwait(t, closed)
	if _, err := conn.native.Status(); err == nil {
		t.Fatal("Close leaked a native handle")
	}
	if err := conn.native.TestEvent(ctx, ffi.TCPTestWaitDisconnect); err != nil {
		t.Fatal(err)
	}
}

func TestTCPConnReportedReadFailurePreventsLaterWrite(t *testing.T) {
	for _, tc := range []struct {
		name  string
		event uint8
	}{
		{"guest-socket-failure", ffi.TCPTestGuestFailureWithoutCancel},
		{"invalid-control", ffi.TCPTestUnexpectedControl},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, ctx := tcpTestConn(t)
			defer conn.Abort()
			if err := conn.SetDeadline(time.Now().Add(tcpTestBound)); err != nil {
				t.Fatal(err)
			}
			// Leave input idle, with capacity in the Unix socket pair. A failed Read must
			// fence later input, not just writers already blocked on guest credit.
			if err := conn.native.TestEvent(ctx, tc.event); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Read(make([]byte, 1)); err == nil || !strings.Contains(err.Error(), "guest TCP read:") {
				t.Fatalf("guest failure did not report its read error: %v", err)
			}
			if n, err := conn.Write([]byte("after failure")); n != 0 || err == nil {
				t.Fatalf("write after reported guest failure: n=%d err=%v", n, err)
			}
			if err := conn.Abort(); err != nil {
				t.Fatalf("guest cleanup: %v", err)
			}
			if err := conn.native.TestEvent(ctx, ffi.TCPTestWaitDisconnect); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTCPConnOrderedGuestEOFRemainsReadableAfterHalfClose(t *testing.T) {
	conn, ctx := tcpTestConn(t)
	defer conn.Abort()
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := conn.native.TestEvent(ctx, ffi.TCPTestWaitFinish); err != nil {
		t.Fatal(err)
	}
	if err := conn.native.TestEvent(ctx, ffi.TCPTestOrderedEOF); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("ordered output must return EOF: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("ordered half-closes must complete successfully: %v", err)
	}
	if err := conn.native.TestEvent(ctx, ffi.TCPTestWaitDisconnect); err != nil {
		t.Fatal(err)
	}
}

func TestTCPConnClosePreservesDeliveryErrorAndCleanupClassification(t *testing.T) {
	for _, tc := range []struct {
		name    string
		event   uint8
		unknown bool
	}{
		{"transport-loss-during-close", ffi.TCPTestDisconnect, true},
		{"failed-delivery-with-acknowledged-cleanup", ffi.TCPTestGuestReset, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, ctx := tcpTestConn(t)
			defer conn.Abort()
			// The fixture withholds credit: these admitted bytes never reached a destination.
			if _, err := conn.Write(make([]byte, 64<<10)); err != nil {
				t.Fatal(err)
			}
			if err := conn.native.TestEvent(ctx, ffi.TCPTestWaitInput); err != nil {
				t.Fatal(err)
			}
			closed := make(chan error, 1)
			go func() { closed <- conn.Close() }()
			if err := conn.native.TestEvent(ctx, ffi.TCPTestWaitFinish); err != nil {
				t.Fatal(err)
			}
			if err := conn.native.TestEvent(ctx, tc.event); err != nil {
				t.Fatal(err)
			}
			err := tcpAwait(t, closed)
			if err == nil || !strings.Contains(err.Error(), "destination") {
				t.Fatalf("Close lost delivery failure: %v", err)
			}
			if errors.Is(err, ErrTCPCleanupUnknown) != tc.unknown {
				t.Fatalf("Close cleanup unknown = %v, want %v: %v", errors.Is(err, ErrTCPCleanupUnknown), tc.unknown, err)
			}
			if err := conn.native.TestEvent(ctx, ffi.TCPTestWaitDisconnect); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.native.Status(); err == nil {
				t.Fatal("Close leaked a native handle")
			}
		})
	}
}

func TestTCPConnAbortReportsTransportLossEvenWithSocketError(t *testing.T) {
	for _, closeSocket := range []bool{false, true} {
		t.Run(map[bool]string{false: "transport-loss-during-abort", true: "transport-loss-and-socket-error"}[closeSocket], func(t *testing.T) {
			conn, ctx := tcpTestConn(t)
			if err := conn.native.TestEvent(ctx, ffi.TCPTestDisconnectOnCancel); err != nil {
				t.Fatal(err)
			}
			if closeSocket {
				// An independent local socket error must not hide the missing guest acknowledgement.
				if err := conn.conn.Close(); err != nil {
					t.Fatal(err)
				}
			}
			aborted := make(chan error, 1)
			go func() { aborted <- conn.Abort() }()
			err := tcpAwait(t, aborted)
			if !errors.Is(err, ErrTCPCleanupUnknown) {
				t.Fatalf("Abort lost unknown cleanup classification: %v", err)
			}
			if closeSocket && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Abort lost local socket error: %v", err)
			}
			if err := conn.native.TestEvent(ctx, ffi.TCPTestWaitCancel); err != nil {
				t.Fatal(err)
			}
			if err := conn.native.TestEvent(ctx, ffi.TCPTestWaitDisconnect); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.native.Status(); err == nil {
				t.Fatal("Abort leaked a native handle")
			}
		})
	}
}
