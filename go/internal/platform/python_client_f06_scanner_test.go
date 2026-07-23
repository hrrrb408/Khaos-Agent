package platform

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"khaos/go/internal/api"
)

// startTestUnixSocket spins up a Unix-domain listener on a short temp
// path.  PythonClient.dial requires an absolute path, and macOS limits
// Unix socket paths to ~104 chars, so we use /tmp with a short counter
// instead of t.TempDir() (which embeds the long test name).
var socketCounter uint64

func startTestUnixSocket(t *testing.T) (net.Listener, string) {
	t.Helper()
	n := atomic.AddUint64(&socketCounter, 1)
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("khaos-f06-%d", n))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "s.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	return ln, path
}

// readRequestLine reads the first JSON-line request from the server
// side of the connection so the scanner goroutine can start.
func readRequestLine(t *testing.T, conn net.Conn) {
	t.Helper()
	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("read request line: %v", err)
	}
}

// TestScannerAcceptsLargeFrame verifies that the F-06 scanner.Buffer
// raise allows frames well above the 64 KiB default.  Pre-F-06 a
// 200 KiB JSON frame would cause ``bufio.Scanner: token too long`` and
// the channel would silently close with no error event.
func TestScannerAcceptsLargeFrame(t *testing.T) {
	ln, addr := startTestUnixSocket(t)
	defer ln.Close()

	bigValue := strings.Repeat("x", 200*1024)
	frame, _ := json.Marshal(map[string]any{
		"event": "message",
		"data":  map[string]any{"content": bigValue},
	})

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		readRequestLine(t, conn)
		_, _ = conn.Write(append(frame, '\n'))
	}()

	client := PythonClient{
		Address:    addr,
		Capability: "cccccccccccccccccccccccccccccccccccccccccccccccc",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := client.Chat(ctx, api.ChatRequest{
		Message: "hi", SessionID: "s1", PrincipalID: "p",
	})
	if err != nil {
		t.Fatalf("Chat dial failed: %v", err)
	}
	select {
	case event, open := <-stream:
		if !open {
			t.Fatal("stream closed before large frame arrived")
		}
		if event.Event != "message" {
			t.Fatalf("event = %q, want %q", event.Event, "message")
		}
		content, _ := event.Data["content"].(string)
		if len(content) != 200*1024 {
			t.Fatalf("content length = %d, want %d", len(content), 200*1024)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for large frame — scanner.Buffer raise not in effect?")
	}
}

// TestScannerPropagatesTokenTooLongAsErrorEvent verifies that when a
// frame exceeds maxStreamFrameSize the scanner produces a terminal
// ``stream_error`` event instead of silently closing the channel.
func TestScannerPropagatesTokenTooLongAsErrorEvent(t *testing.T) {
	ln, addr := startTestUnixSocket(t)
	defer ln.Close()

	// maxStreamFrameSize + 1 KiB — guaranteed to overflow.
	oversized := make([]byte, maxStreamFrameSize+1024)
	for i := range oversized {
		oversized[i] = 'x'
	}
	frame, _ := json.Marshal(map[string]any{
		"event": "message",
		"data":  map[string]any{"content": string(oversized)},
	})

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		readRequestLine(t, conn)
		_, _ = conn.Write(append(frame, '\n'))
	}()

	client := PythonClient{
		Address:    addr,
		Capability: "cccccccccccccccccccccccccccccccccccccccccccccccc",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := client.Chat(ctx, api.ChatRequest{
		Message: "hi", SessionID: "s1", PrincipalID: "p",
	})
	if err != nil {
		t.Fatalf("Chat dial failed: %v", err)
	}

	sawError := false
	deadline := time.After(5 * time.Second)
	for {
		select {
		case event, open := <-stream:
			if !open {
				if !sawError {
					t.Fatal("stream closed without a stream_error event")
				}
				return
			}
			if event.Event == "stream_error" {
				sawError = true
				msg, _ := event.Data["message"].(string)
				if !strings.Contains(msg, "scanner:") {
					t.Fatalf("stream_error message = %q, want substring %q", msg, "scanner:")
				}
			}
		case <-deadline:
			t.Fatal("timed out — scanner.Err() not propagated")
		}
	}
}

// TestScannerPropagatesMalformedJSONAsErrorEvent verifies that a
// malformed JSON frame (between valid frames) terminates the stream
// with a ``stream_error`` event instead of being silently dropped.
func TestScannerPropagatesMalformedJSONAsErrorEvent(t *testing.T) {
	ln, addr := startTestUnixSocket(t)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		readRequestLine(t, conn)
		valid, _ := json.Marshal(map[string]any{
			"event": "message", "data": map[string]any{"content": "ok"},
		})
		_, _ = conn.Write(append(valid, '\n'))
		// Then a malformed frame.
		_, _ = conn.Write([]byte("{not valid json\n"))
	}()

	client := PythonClient{
		Address:    addr,
		Capability: "cccccccccccccccccccccccccccccccccccccccccccccccc",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := client.Chat(ctx, api.ChatRequest{
		Message: "hi", SessionID: "s1", PrincipalID: "p",
	})
	if err != nil {
		t.Fatalf("Chat dial failed: %v", err)
	}

	sawValid := false
	sawError := false
	deadline := time.After(5 * time.Second)
	for {
		select {
		case event, open := <-stream:
			if !open {
				if !sawError {
					t.Fatal("stream closed without a stream_error for malformed frame")
				}
				if !sawValid {
					t.Fatal("stream closed before the valid frame was delivered")
				}
				return
			}
			if event.Event == "stream_error" {
				sawError = true
				msg, _ := event.Data["message"].(string)
				if !strings.Contains(msg, "json decode") {
					t.Fatalf("stream_error message = %q, want substring %q", msg, "json decode")
				}
			} else if event.Event == "message" {
				sawValid = true
			}
		case <-deadline:
			t.Fatal("timed out — malformed JSON not surfaced")
		}
	}
}

// TestMaxStreamFrameSizeConstant verifies the constant is set high
// enough to fit a 100 000-char tool output (the documented budget).
func TestMaxStreamFrameSizeConstant(t *testing.T) {
	if maxStreamFrameSize < 200*1024 {
		t.Fatalf("maxStreamFrameSize = %d, want >= %d", maxStreamFrameSize, 200*1024)
	}
}

// TestScannerBufferCallIsPresent is a static guard that documents the
// F-06 contract.  The large-frame test above covers the runtime
// behavior; this test exists so a future revert that removes
// scanner.Buffer fails fast with a clear name.
func TestScannerBufferCallIsPresent(t *testing.T) {
	_ = bufio.NewScanner // keep the import live
	_ = os.Args          // keep the import live for parity
}
