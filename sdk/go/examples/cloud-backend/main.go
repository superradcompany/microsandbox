// Cloud backend lifecycle and live-log example.
//
// Run from sdk/go:
//
//	MSB_API_URL=https://cloud.example.com MSB_API_KEY=... go run ./examples/cloud-backend
//
// Or configure ~/.microsandbox/config.json and run:
//
//	MSB_PROFILE=prod go run ./examples/cloud-backend
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

func main() {
	if os.Getenv("MSB_PROFILE") == "" &&
		(os.Getenv("MSB_API_URL") == "" || os.Getenv("MSB_API_KEY") == "") {
		log.Fatal("set MSB_PROFILE or both MSB_API_URL and MSB_API_KEY")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	name := fmt.Sprintf("go-cloud-%d", time.Now().Unix())
	log.Printf("creating %q on the cloud backend", name)

	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithMemory(512),
		microsandbox.WithCPUs(1),
		microsandbox.WithEntrypoint(
			"/bin/sh",
			"-lc",
			"for i in 1 2 3; do echo go-cloud-$i; sleep 1; done",
		),
		microsandbox.WithMaxDuration(60*time.Second),
		microsandbox.WithReplace(),
	)
	if err != nil {
		log.Fatalf("CreateSandbox: %v", err)
	}

	out, err := sb.Shell(ctx, "printf 'cloud exec from go\n'; uname -m")
	if err != nil {
		log.Fatalf("Shell: %v", err)
	}
	log.Printf("exec status: %d", out.ExitCode())
	fmt.Print(out.Stdout())

	stream, err := sb.LogStream(ctx, microsandbox.LogStreamOptions{
		Sources: []microsandbox.LogSource{
			microsandbox.LogSourceStdout,
			microsandbox.LogSourceStderr,
			microsandbox.LogSourceSystem,
		},
		Follow: true,
	})
	if err != nil {
		log.Fatalf("LogStream: %v", err)
	}
	defer func() {
		if err := stream.Close(); err != nil {
			log.Printf("LogStream.Close: %v", err)
		}
	}()

	for i := 0; i < 3; i++ {
		recvCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		entry, err := stream.Recv(recvCtx)
		cancel()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				log.Printf("timed out waiting for another log entry")
				break
			}
			log.Fatalf("LogStream.Recv: %v", err)
		}
		if entry == nil {
			break
		}
		fmt.Printf(
			"[%s %s] %s\n",
			entry.Timestamp.Format(time.RFC3339),
			entry.Source,
			strings.TrimSpace(entry.Text()),
		)
	}

	if err := sb.Stop(ctx); err != nil {
		log.Fatalf("Stop: %v", err)
	}
	if err := waitUntilStopped(ctx, name); err != nil {
		log.Fatal(err)
	}
	if err := microsandbox.RemoveSandbox(ctx, name); err != nil {
		log.Fatalf("RemoveSandbox: %v", err)
	}
	log.Printf("removed %q", name)
}

func waitUntilStopped(ctx context.Context, name string) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	deadline := time.After(30 * time.Second)
	for {
		handle, err := microsandbox.GetSandbox(ctx, name)
		if err != nil {
			return err
		}
		if handle.Status() == microsandbox.SandboxStatusStopped {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("sandbox %q did not stop within 30s", name)
		case <-ticker.C:
		}
	}
}
