package ffi

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Decode the additive byte fields when present. Their presence (including an
// empty string) matters. Valid UTF-8 streams and old native libraries use text.
func decodeCollectedOutput(payload string) (*ExecResult, error) {
	var raw struct {
		Stdout    string  `json:"stdout"`
		Stderr    string  `json:"stderr"`
		StdoutB64 *string `json:"stdout_b64"`
		StderrB64 *string `json:"stderr_b64"`
		ExitCode  *int    `json:"exit_code"`
	}
	if err := json.Unmarshal([]byte(payload), &raw); err != nil {
		return nil, fmt.Errorf("parse exec response: %w", err)
	}
	decode := func(encoded *string, legacy, stream string) (string, error) {
		if encoded == nil {
			return legacy, nil
		}
		data, err := base64.StdEncoding.DecodeString(*encoded)
		if err != nil {
			return "", fmt.Errorf("decode exec %s: %w", stream, err)
		}
		return string(data), nil
	}
	stdout, err := decode(raw.StdoutB64, raw.Stdout, "stdout")
	if err != nil {
		return nil, err
	}
	stderr, err := decode(raw.StderrB64, raw.Stderr, "stderr")
	if err != nil {
		return nil, err
	}
	code := -1
	if raw.ExitCode != nil {
		code = *raw.ExitCode
	}
	return &ExecResult{Stdout: stdout, Stderr: stderr, ExitCode: code}, nil
}
