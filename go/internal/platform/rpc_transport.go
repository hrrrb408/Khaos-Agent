package platform

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"sync"
)

// RPCTransport owns the process-to-process connection establishment policy.
// The RPC client owns the authenticated envelope; a transport must only
// return a connected byte stream and must not interpret application messages.
// Keeping this port small makes connection lifecycle tests independent from
// the Python service implementation and leaves room for a native transport
// without duplicating protocol logic.
type RPCTransport interface {
	Dial(ctx context.Context, address string) (net.Conn, error)
}

// UnixRPCTransport is the production transport for the Python agent.  Python
// RPC addresses are Unix-domain socket paths, never host:port strings.
type UnixRPCTransport struct{}

// Dial connects to one absolute Unix-domain socket and applies the caller's
// deadline to the connection.  Relative paths and TCP-style addresses fail
// closed before any network operation is attempted.
func (UnixRPCTransport) Dial(ctx context.Context, address string) (net.Conn, error) {
	if !filepath.IsAbs(address) {
		return nil, fmt.Errorf("Python AgentService requires an absolute Unix socket path")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", address)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

// RPCConnection is the lifecycle owner for one authenticated RPC stream.
// It embeds net.Conn so existing framing/streaming code can consume it as a
// byte stream, while Close also tears down the context cancellation hook.
// Closing is idempotent at the transport boundary because callers may close
// on both an error path and a stream goroutine's deferred cleanup.
type RPCConnection struct {
	net.Conn
	stopContext func()
	closeOnce   sync.Once
	closeErr    error
}

// OpenRPCConnection dials through the supplied transport and binds the
// connection lifetime to ctx.  Cancellation closes the underlying stream so
// blocked JSON decoders and scanners are released promptly.
func OpenRPCConnection(ctx context.Context, transport RPCTransport, address string) (*RPCConnection, error) {
	if transport == nil {
		transport = UnixRPCTransport{}
	}
	conn, err := transport.Dial(ctx, address)
	if err != nil {
		return nil, err
	}
	rpc := &RPCConnection{Conn: conn}
	stop := context.AfterFunc(ctx, func() {
		_ = rpc.Close()
	})
	rpc.stopContext = func() { stop() }
	return rpc, nil
}

// Close releases the cancellation hook before closing the byte stream.
func (c *RPCConnection) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		if c.stopContext != nil {
			c.stopContext()
			c.stopContext = nil
		}
		if c.Conn != nil {
			c.closeErr = c.Conn.Close()
		}
	})
	return c.closeErr
}
