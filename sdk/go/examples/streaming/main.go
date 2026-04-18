// Streaming exec example for the microsandbox Go SDK.
//
// Exercises: ExecStream, ExecEvent (Started/Stdout/Stderr/Exited/Done),
// Signal (SIGTERM), context cancellation of Recv.
//
// Build: from sdk/go, run
//
//	cargo build -p microsandbox-go-ffi
//	CGO_LDFLAGS="-L$(git rev-parse --show-toplevel)/target/debug" \
//	  go run ./examples/streaming
//
// Requires a running microsandbox daemon.
package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"syscall"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	name := fmt.Sprintf("go-sdk-stream-%d", time.Now().Unix())
	log.Printf("creating sandbox %q", name)

	sb, err := microsandbox.NewSandbox(ctx, name, microsandbox.WithImage("alpine:3.19"))
	if err != nil {
		log.Fatalf("NewSandbox: %v", err)
	}
	defer func() {
		stopCtx, c := context.WithTimeout(context.Background(), 30*time.Second)
		defer c()
		_, _ = sb.StopAndWait(stopCtx)
		_ = sb.Close()
		_ = microsandbox.RemoveSandbox(context.Background(), name)
	}()

	// ---- Scenario 1: collect all events from a short command. ---------------
	fmt.Println("-- scenario 1: stream short command to completion")
	if err := collectShortCommand(ctx, sb); err != nil {
		log.Fatalf("short command: %v", err)
	}

	// ---- Scenario 2: send SIGTERM to a long-running process. ----------------
	fmt.Println("-- scenario 2: SIGTERM a long-running process")
	if err := sigtermLongCommand(ctx, sb); err != nil {
		log.Fatalf("SIGTERM: %v", err)
	}

	// ---- Scenario 3: cancel the ctx while waiting on Recv. ------------------
	fmt.Println("-- scenario 3: cancel ctx while waiting on Recv")
	if err := cancelDuringRecv(ctx, sb); err != nil {
		log.Fatalf("ctx cancel: %v", err)
	}

	fmt.Println("OK — streaming example passed")
}

func collectShortCommand(ctx context.Context, sb *microsandbox.Sandbox) error {
	h, err := sb.ShellStream(ctx, "echo out-line; echo err-line >&2; exit 3")
	if err != nil {
		return fmt.Errorf("ShellStream: %w", err)
	}
	defer h.Close()

	var stdout, stderr strings.Builder
	var pid uint32
	exitCode := -1
	for {
		ev, err := h.Recv(ctx)
		if err != nil {
			return fmt.Errorf("Recv: %w", err)
		}
		switch ev.Kind {
		case microsandbox.ExecEventStarted:
			pid = ev.PID
		case microsandbox.ExecEventStdout:
			stdout.Write(ev.Data)
		case microsandbox.ExecEventStderr:
			stderr.Write(ev.Data)
		case microsandbox.ExecEventExited:
			exitCode = ev.ExitCode
		case microsandbox.ExecEventDone:
			fmt.Printf("  started pid=%d exit=%d\n", pid, exitCode)
			fmt.Printf("  stdout: %q\n", strings.TrimSpace(stdout.String()))
			fmt.Printf("  stderr: %q\n", strings.TrimSpace(stderr.String()))
			if exitCode != 3 {
				return fmt.Errorf("want exit 3, got %d", exitCode)
			}
			if !strings.Contains(stdout.String(), "out-line") {
				return fmt.Errorf("missing 'out-line' in stdout: %q", stdout.String())
			}
			if !strings.Contains(stderr.String(), "err-line") {
				return fmt.Errorf("missing 'err-line' in stderr: %q", stderr.String())
			}
			return nil
		}
	}
}

func sigtermLongCommand(ctx context.Context, sb *microsandbox.Sandbox) error {
	h, err := sb.ShellStream(ctx, "sleep 60")
	if err != nil {
		return fmt.Errorf("ShellStream: %w", err)
	}
	defer h.Close()

	// Wait for the Started event before signalling.
	for {
		ev, err := h.Recv(ctx)
		if err != nil {
			return fmt.Errorf("Recv (waiting Started): %w", err)
		}
		if ev.Kind == microsandbox.ExecEventStarted {
			fmt.Printf("  started pid=%d\n", ev.PID)
			break
		}
	}

	if err := h.Signal(ctx, int(syscall.SIGTERM)); err != nil {
		return fmt.Errorf("Signal SIGTERM: %w", err)
	}

	deadline := time.After(10 * time.Second)
	gotExited := false
	for {
		select {
		case <-deadline:
			return fmt.Errorf("stream did not end within 10s")
		default:
		}
		ev, err := h.Recv(ctx)
		if err != nil {
			return fmt.Errorf("Recv after signal: %w", err)
		}
		if ev.Kind == microsandbox.ExecEventExited {
			gotExited = true
			fmt.Printf("  exited after SIGTERM: code=%d\n", ev.ExitCode)
		}
		if ev.Kind == microsandbox.ExecEventDone {
			if !gotExited {
				return fmt.Errorf("never received Exited after SIGTERM")
			}
			return nil
		}
	}
}

func cancelDuringRecv(outer context.Context, sb *microsandbox.Sandbox) error {
	h, err := sb.ShellStream(outer, "sleep 60")
	if err != nil {
		return fmt.Errorf("ShellStream: %w", err)
	}
	defer h.Close()

	// Drain until Started so the process is alive.
	for {
		ev, err := h.Recv(outer)
		if err != nil {
			return fmt.Errorf("Recv Started: %w", err)
		}
		if ev.Kind == microsandbox.ExecEventStarted {
			break
		}
	}

	recvCtx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := h.Recv(recvCtx)
		errc <- err
	}()
	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case err := <-errc:
		if err == nil {
			return fmt.Errorf("expected ctx error, got nil")
		}
		fmt.Printf("  Recv returned promptly after cancel: %v\n", err)
	case <-time.After(5 * time.Second):
		return fmt.Errorf("Recv did not return within 5s after cancel")
	}

	// Terminate the sleep so Close cleans up fast.
	_ = h.Signal(outer, int(syscall.SIGKILL))
	return nil
}
