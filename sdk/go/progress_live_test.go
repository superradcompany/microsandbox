//go:build progress_live && microsandbox_ffi_path

package microsandbox

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestCreationProgressLive(t *testing.T) {
	snapshot := os.Getenv("MSB_PROGRESS_SNAPSHOT")
	if snapshot == "" {
		t.Skip("requires installed checksum checkpoint fixture")
	}
	for _, observed := range []bool{true, false} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		start := time.Now()
		events, result := RestoreSandboxWithProgress(ctx, snapshot, fmt.Sprintf("progress-go-%d-%t", os.Getpid(), observed), WithForked())
		activating := false
		if observed {
			for event := range events {
				t.Logf("%s: %+v", time.Since(start), event)
				activating = activating || event.Progress.Phase == "activating"
			}
		}
		created := <-result
		cancel()
		if created.Err != nil {
			t.Fatal(created.Err)
		}
		t.Logf("created observed=%t in %s", observed, time.Since(start))
		output, err := created.Sandbox.Exec(context.Background(), "sha256sum", []string{"-c", "/work/hash"})
		stopErr := created.Sandbox.Kill(context.Background())
		created.Sandbox.Close()
		if err != nil {
			t.Fatal(err)
		}
		if stopErr != nil {
			t.Fatal(stopErr)
		}
		t.Logf("checksum result: %+v", output)
		if !output.Success() {
			t.Fatal(output.Stderr())
		}
		if observed && !activating {
			t.Fatal("missing activating event")
		}
	}
}
