package ws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"khaos/go/internal/api"
	"khaos/go/internal/ws/websocket"
)

// HandleWebSocket handles a stream-like connection without external WebSocket dependencies.
func HandleWebSocket(hub *Hub, agent api.AgentClient, w http.ResponseWriter, r *http.Request) {
	HandleStream(hub, agent, w, r)
}

// HandleStream serves chunked NDJSON chat events.
func HandleStream(hub *Hub, agent api.AgentClient, w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimPrefix(r.URL.Path, "/api/chat/")
	sessionID = strings.TrimSuffix(sessionID, "/stream")
	sessionID = strings.Trim(strings.TrimPrefix(sessionID, "/api/ws/"), "/")
	if sessionID == "" || sessionID == "new" {
		sessionID = fmt.Sprintf("session-%d", time.Now().UnixNano())
	}

	var req api.ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	req.SessionID = sessionID

	stream, err := agent.Chat(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	conn := websocket.NewConn(w)
	if hub != nil {
		hub.Register(conn, sessionID)
		defer hub.Unregister(conn, sessionID)
	}
	flusher, _ := w.(http.Flusher)
	for event := range stream {
		if err := conn.WriteJSON(event); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}
