package microsandbox

import "testing"

func TestVolumeName(t *testing.T) {
	v := &Volume{name: "my-volume"}
	if v.Name() != "my-volume" {
		t.Errorf("Name() = %q, want %q", v.Name(), "my-volume")
	}
}
