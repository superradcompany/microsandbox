// Package microsandbox is the Go SDK for microsandbox, a microVM sandbox
// runtime. It supports creating and managing sandboxes, executing commands,
// reading and writing files inside a sandbox, and managing named volumes.
//
// The SDK calls into the microsandbox Rust library via CGO. Build the
// companion staticlib first:
//
//	cargo build -p microsandbox-go-ffi
package microsandbox
