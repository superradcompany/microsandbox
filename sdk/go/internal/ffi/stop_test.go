package ffi

import (
	"encoding/json"
	"testing"
)

func TestStopLifecycleRequestDistinguishesUnboundedAndZero(t *testing.T) {
	operation, _ := stopLifecycleRequest(nil)
	if operation != "stop_gracefully" {
		t.Fatalf("unbounded Stop uses %q, want distinct graceful operation", operation)
	}
	for _, timeout := range []uint64{0, 30_000} {
		operation, options := stopLifecycleRequest(&timeout)
		if operation != "stop_with_timeout" || options.TimeoutMs != timeout {
			t.Fatalf("bounded Stop lost deadline: %s %+v", operation, options)
		}
		data, err := json.Marshal(options)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			t.Fatal(err)
		}
		if _, present := fields["timeout_ms"]; !present {
			t.Fatal("explicit zero must remain present on the native boundary")
		}
	}
}
