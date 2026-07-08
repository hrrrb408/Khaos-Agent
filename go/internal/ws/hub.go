// Package ws provides stream connection tracking for gateway sessions.
package ws

import (
	"sync"

	"khaos/go/internal/api"
)

// Connection is the JSON connection contract used by Hub.
type Connection interface {
	WriteJSON(v any) error
	ReadJSON(v any) error
	Close() error
}

// Hub manages broadcast connections and session tracking.
type Hub struct {
	mu         sync.RWMutex
	clients    map[string]map[Connection]bool
	register   chan *clientInfo
	unregister chan *clientInfo
	broadcast  chan broadcastMsg
	start      sync.Once
}

type clientInfo struct {
	conn      Connection
	sessionID string
}

type broadcastMsg struct {
	sessionID string
	event     api.ChatEvent
}

// NewHub creates a connection hub.
func NewHub() *Hub {
	return &Hub{
		clients:    map[string]map[Connection]bool{},
		register:   make(chan *clientInfo),
		unregister: make(chan *clientInfo),
		broadcast:  make(chan broadcastMsg, 16),
	}
}

// Run starts the hub event loop.
func (h *Hub) Run() {
	h.start.Do(h.eventLoop)
}

// Register adds a connection for a session.
func (h *Hub) Register(conn Connection, sessionID string) {
	h.register <- &clientInfo{conn: conn, sessionID: sessionID}
}

// Unregister removes a connection from a session.
func (h *Hub) Unregister(conn Connection, sessionID string) {
	h.unregister <- &clientInfo{conn: conn, sessionID: sessionID}
}

// Broadcast sends an event to all tracked connections for a session.
func (h *Hub) Broadcast(sessionID string, event api.ChatEvent) {
	h.broadcast <- broadcastMsg{sessionID: sessionID, event: event}
}

// HasClients reports whether a session has active clients.
func (h *Hub) HasClients(sessionID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients[sessionID]) > 0
}

// ClientCount returns the total active connection count.
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	total := 0
	for _, clients := range h.clients {
		total += len(clients)
	}
	return total
}

func (h *Hub) eventLoop() {
	for {
		select {
		case info := <-h.register:
			h.mu.Lock()
			if h.clients[info.sessionID] == nil {
				h.clients[info.sessionID] = map[Connection]bool{}
			}
			h.clients[info.sessionID][info.conn] = true
			h.mu.Unlock()
		case info := <-h.unregister:
			h.mu.Lock()
			if clients := h.clients[info.sessionID]; clients != nil {
				delete(clients, info.conn)
				if len(clients) == 0 {
					delete(h.clients, info.sessionID)
				}
			}
			h.mu.Unlock()
		case msg := <-h.broadcast:
			h.mu.RLock()
			clients := make([]Connection, 0, len(h.clients[msg.sessionID]))
			for conn := range h.clients[msg.sessionID] {
				clients = append(clients, conn)
			}
			h.mu.RUnlock()
			for _, conn := range clients {
				_ = conn.WriteJSON(msg.event)
			}
		}
	}
}
