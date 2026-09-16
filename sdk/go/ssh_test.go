package microsandbox

import (
	"testing"
	"time"
)

func TestSSHInactivityTimeoutSeconds(t *testing.T) {
	tests := []struct {
		name    string
		timeout *time.Duration
		want    *uint64
		wantErr bool
	}{
		{name: "inherit"},
		{name: "disabled", timeout: durationPtr(0), want: uint64Ptr(0)},
		{name: "configured", timeout: durationPtr(30 * time.Second), want: uint64Ptr(30)},
		{name: "negative", timeout: durationPtr(-time.Second), wantErr: true},
		{name: "sub-second rounds up", timeout: durationPtr(time.Nanosecond), want: uint64Ptr(1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sshInactivityTimeoutSeconds(tt.timeout)
			if (err != nil) != tt.wantErr {
				t.Fatalf("sshInactivityTimeoutSeconds() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.want == nil {
				if got != nil {
					t.Fatalf("sshInactivityTimeoutSeconds() = %v, want nil", *got)
				}
				return
			}
			if got == nil || *got != *tt.want {
				t.Fatalf("sshInactivityTimeoutSeconds() = %v, want %v", got, *tt.want)
			}
		})
	}
}

func durationPtr(value time.Duration) *time.Duration {
	return &value
}

func uint64Ptr(value uint64) *uint64 {
	return &value
}
