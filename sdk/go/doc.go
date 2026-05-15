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
// function. It downloads the microsandbox runtime (msb, libkrunfw, and the
// Go FFI shared library) into ~/.microsandbox/ on first use and is a no-op
// on subsequent calls:
//
//	if err := microsandbox.EnsureInstalled(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
// Set MICROSANDBOX_LIB_PATH to point at a locally built
// libmicrosandbox_go_ffi to skip the download during development.
package microsandbox
