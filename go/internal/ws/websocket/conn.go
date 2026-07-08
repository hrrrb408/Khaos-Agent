// Package websocket defines the minimal connection type used by the in-process hub.
package websocket

import (
	"encoding/json"
	"io"
	"sync"
)

// Conn is a small JSON writer abstraction for stream-like connections.
type Conn struct {
	mu sync.Mutex
	w  io.Writer
}

// NewConn creates a connection backed by a writer.
func NewConn(w io.Writer) *Conn {
	return &Conn{w: w}
}

// WriteJSON writes one JSON object followed by a newline.
func (c *Conn) WriteJSON(value any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.w == nil {
		return nil
	}
	if err := json.NewEncoder(c.w).Encode(value); err != nil {
		return err
	}
	return nil
}

// ReadJSON is present for compatibility with bidirectional connection interfaces.
func (c *Conn) ReadJSON(value any) error {
	return io.EOF
}

// Close closes the underlying writer when it supports io.Closer.
func (c *Conn) Close() error {
	if closer, ok := c.w.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
