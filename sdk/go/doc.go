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
// At program startup, call EnsureInstalled once before any other SDK
// function. It extracts the embedded FFI library, downloads the
// microsandbox runtime (msb, libkrunfw) into ~/.microsandbox/ on first
// use, and is a no-op on subsequent calls:
//
//	if err := microsandbox.EnsureInstalled(ctx); err != nil {
//	    log.Fatal(err)
//	}
package microsandbox
