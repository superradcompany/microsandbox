package ffi

import "testing"

func TestContextInfoRequiresRetainedMetadata(t *testing.T) {
	// Older native registrations omit the new metadata field. Do not answer
	// by querying today's default, which could describe a different backend.
	old := &Context{kind: "local"}
	_, err := old.Info()
	nativeErr, ok := err.(*Error)
	if !ok || nativeErr.Kind != KindUnsupportedOperation {
		t.Fatalf("expected unsupported metadata, got %v", err)
	}
}
