package microsandbox

import (
	"encoding/json"
	"testing"
)

func TestJobOutputPreservesBytesAndCursor(t *testing.T) {
	var entry JobLogEntry
	if err := json.Unmarshal([]byte(`{"timestamp":1,"source":"stdout","data_base64":"/wAK","cursor":"job_1:1"}`), &entry); err != nil {
		t.Fatal(err)
	}
	if string(entry.Data) != string([]byte{255, 0, 10}) || entry.Cursor != "job_1:1" {
		t.Fatalf("bad output: %#v", entry)
	}
}
func TestDetachedOptionsReuseExistingExecOptions(t *testing.T) {
	config := jobExecConfig{ExecConfig: ExecConfig{StdinPipe: true}}
	options := []JobExecOption{WithExecCwd("/tmp"), WithExecTTY(false), WithExecStdinNull()}
	for _, option := range options {
		option.applyJob(&config)
	}
	if config.Cwd != "/tmp" || config.StdinPipe {
		t.Fatalf("bad options: %#v", config)
	}
}
