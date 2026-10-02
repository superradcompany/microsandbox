package ffi

import "testing"

func TestCollectedOutputPreservesBinary(t *testing.T) {
	out, err := decodeCollectedOutput(`{"stdout":"discarded","stderr":"discarded","stdout_b64":"Yf8AYg==","stderr_b64":"Y/4AZA==","exit_code":7}`)
	if err != nil {
		t.Fatal(err)
	}
	if out.Stdout != string([]byte{'a', 255, 0, 'b'}) || out.Stderr != string([]byte{'c', 254, 0, 'd'}) || out.ExitCode != 7 {
		t.Fatalf("binary output changed: %#v", out)
	}
}

func TestCollectedOutputAcceptsLegacyNativeResponse(t *testing.T) {
	out, err := decodeCollectedOutput(`{"stdout":"hello","stderr":"error","exit_code":null}`)
	if err != nil {
		t.Fatal(err)
	}
	if out.Stdout != "hello" || out.Stderr != "error" || out.ExitCode != -1 {
		t.Fatalf("legacy output changed: %#v", out)
	}
}

func TestCollectedOutputEmptyByteFieldsOverrideLegacyText(t *testing.T) {
	out, err := decodeCollectedOutput(`{"stdout":"wrong","stderr":"wrong","stdout_b64":"","stderr_b64":"","exit_code":0}`)
	if err != nil {
		t.Fatal(err)
	}
	if out.Stdout != "" || out.Stderr != "" || out.ExitCode != 0 {
		t.Fatalf("empty output changed: %#v", out)
	}
}

func TestCollectedOutputRejectsCorruptBase64(t *testing.T) {
	for _, payload := range []string{`{"stdout_b64":"!"}`, `{"stderr_b64":"!"}`} {
		if _, err := decodeCollectedOutput(payload); err == nil {
			t.Fatalf("accepted corrupt output: %s", payload)
		}
	}
}
