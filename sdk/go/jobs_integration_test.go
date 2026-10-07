//go:build microsandbox_ffi_path && !smoke

package microsandbox

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

func TestManagedJobIntegration(t *testing.T) {
	name := os.Getenv("MSB_JOB_TEST_SANDBOX")
	if name == "" {
		t.Skip("requires a disposable VM and MSB_JOB_TEST_SANDBOX")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	handle, err := GetSandbox(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := handle.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close()
	job, err := sb.ExecDetached(ctx, "cat", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = job.Kill(context.Background()); _ = job.Close() }()
	attachment, err := job.Attach(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer attachment.Close()
	_, err = job.Attach(ctx)
	var jobError *JobError
	if !errors.As(err, &jobError) || jobError.Code != "input_busy" {
		t.Fatalf("expected input exclusion, got %v", err)
	}
	if err := attachment.WriteStdin(ctx, []byte{255, 0, 10}); err != nil {
		t.Fatal(err)
	}
	event, err := attachment.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if event.Output == nil || string(event.Output.Data) != string([]byte{255, 0, 10}) {
		t.Fatalf("bad output %#v", event)
	}
	if err := attachment.Detach(ctx); err != nil {
		t.Fatal(err)
	}
	found, err := handle.GetJob(ctx, job.ID())
	if err != nil {
		t.Fatal(err)
	}
	defer found.Close()
	second, err := found.Attach(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := second.WriteStdin(ctx, []byte("reattached\n")); err != nil {
		t.Fatal(err)
	}
	waiting, endWait := context.WithTimeout(ctx, 25*time.Millisecond)
	_, err = found.Wait(waiting)
	endWait()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait cancellation: %v", err)
	}
	if err := found.EOF(ctx); err != nil {
		t.Fatal(err)
	}
	status, err := found.Wait(ctx)
	if err != nil || !status.Success {
		t.Fatalf("wait: %#v %v", status, err)
	}
	logs, err := found.Logs(ctx, JobLogOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var bytes []byte
	for _, entry := range logs {
		bytes = append(bytes, entry.Data...)
	}
	if string(bytes) != string(append([]byte{255, 0, 10}, []byte("reattached\n")...)) {
		t.Fatalf("logs: %q", bytes)
	}
	sleepy, err := sb.ExecDetached(ctx, "sleep", []string{"30"})
	if err != nil {
		t.Fatal(err)
	}
	defer sleepy.Close()
	defer sleepy.Kill(context.Background())
	stream, err := sleepy.FollowLogs(ctx, JobLogOptions{})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := stream.Next(ctx); done <- err }()
	time.Sleep(25 * time.Millisecond)
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, io.EOF) {
		t.Fatalf("stream close: %v", err)
	}
}

func TestExecStreamDeadlineIntegration(t *testing.T) {
	name := os.Getenv("MSB_JOB_TEST_SANDBOX")
	if name == "" {
		t.Skip("requires a disposable VM and MSB_JOB_TEST_SANDBOX")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	handle, err := GetSandbox(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := handle.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close()
	for _, tty := range []bool{false, true} {
		stream, err := sb.ExecStream(ctx, "sleep", []string{"30"}, WithExecTimeout(time.Second), WithExecTTY(tty))
		if err != nil {
			t.Fatal(err)
		}
		defer stream.Close()
		defer stream.Kill(context.Background())
		// No output consumer is necessary for the native deadline to fire.
		time.Sleep(1500 * time.Millisecond)
		_, err = stream.Collect(ctx)
		if !IsKind(err, ErrExecTimeout) {
			t.Fatalf("expected exec timeout, got %v", err)
		}
	}
}
