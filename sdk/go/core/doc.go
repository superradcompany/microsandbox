// Package microsandbox is the Go SDK for microsandbox, a microVM sandbox
// runtime. It supports creating and managing sandboxes, executing commands,
// reading and writing files inside a sandbox, and managing named volumes.
//
// # Installation
//
// Fetch the SDK with the standard Go toolchain:
//
//	go get github.com/superradcompany/microsandbox/sdk/go
//
// The SDK works out of the box: the FFI library is embedded in the Go
// binary and loads on first use. EnsureRuntime is optional and only
// governs the msb + libkrunfw runtime download into the install dir
// ($MSB_HOME, default ~/.microsandbox).
// Call it at startup if you want install errors surfaced up front:
//
//	if _, err := microsandbox.EnsureRuntime(ctx, microsandbox.RuntimeConfig{}, microsandbox.InstallOptions{}); err != nil {
//	    log.Fatal(err)
//	}
package microsandbox
