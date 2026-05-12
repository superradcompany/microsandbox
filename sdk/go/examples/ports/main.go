// Port-publishing example for the microsandbox Go SDK.
//
// Publishes guest port 7777 on host port 17777, runs a netcat listener
// inside the sandbox, dials the host port from the Go process, and
// prints the byte-for-byte payload that came back.
//
// Build: from sdk/go, run
//
//	go run ./examples/ports
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

const (
	hostPort  = 17777
	guestPort = 7777
	payload   = "hello-from-microvm"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if err := microsandbox.EnsureInstalled(ctx); err != nil {
		log.Fatalf("EnsureInstalled: %v", err)
	}

	name := fmt.Sprintf("go-sdk-ports-%d", time.Now().Unix())
	log.Printf("creating sandbox %q with %d -> %d (TCP)", name, hostPort, guestPort)

	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithPorts(map[uint16]uint16{hostPort: guestPort}),
	)
	if err != nil {
		log.Fatalf("CreateSandbox: %v", err)
	}
	defer func() {
		stopCtx, c := context.WithTimeout(context.Background(), 30*time.Second)
		defer c()
		_, _ = sb.StopAndWait(stopCtx)
		_ = sb.Close()
		_ = microsandbox.RemoveSandbox(context.Background(), name)
	}()

	// Background: bind a listener inside the guest and pipe `payload` to
	// the first connection. ShellStream lets us run it without blocking.
	cmd := fmt.Sprintf("printf '%s' | nc -l -p %d", payload, guestPort)
	h, err := sb.ShellStream(ctx, cmd)
	if err != nil {
		log.Fatalf("ShellStream: %v", err)
	}
	defer h.Close()

	// Wait for nc to be listening before dialing — TCP doesn't queue
	// connections to a closed port.
	addr := fmt.Sprintf("localhost:%d", hostPort)
	conn, err := dialWithRetry(addr, 10, 200*time.Millisecond)
	if err != nil {
		log.Fatalf("dial host port: %v", err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatalf("read host->guest: %v", err)
	}
	got := string(buf[:n])
	if !strings.Contains(got, payload) {
		log.Fatalf("payload mismatch: got %q want %q", got, payload)
	}
	fmt.Printf("  read %d bytes from host port %d -> %q\n", n, hostPort, got)
	fmt.Println("OK — port-publishing example passed")
}

func dialWithRetry(addr string, attempts int, delay time.Duration) (net.Conn, error) {
	var (
		conn net.Conn
		err  error
	)
	for i := 0; i < attempts; i++ {
		conn, err = net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			return conn, nil
		}
		time.Sleep(delay)
	}
	return nil, err
}
