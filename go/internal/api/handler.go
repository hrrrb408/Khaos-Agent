package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"khaos/go/internal/auth"
	"khaos/go/internal/metrics"
	"khaos/go/internal/rate"
)

// Handler serves Khaos Phase 2 REST and SSE endpoints.
type Handler struct {
	agent     AgentClient
	memory    MemoryClient
	audit     AuditClient
	subagents SubagentClient
	config    ConfigStore
	limiter   *rate.TokenBucket
	metrics   *metrics.Collector
	apiKey    string
	startedAt time.Time
	mu        sync.Mutex
	streams   map[string]<-chan ChatEvent
	sessions  map[string]ChatRequest
	tools     []map[string]any
}

// WithAudit attaches an audit client so GET /api/audit is served.
func (h *Handler) WithAudit(audit AuditClient) *Handler {
	h.audit = audit
	return h
}

// NewHandler creates an API handler.
func NewHandler(agent AgentClient, memory MemoryClient, config ConfigStore, apiKey string, limiter *rate.TokenBucket) *Handler {
	return &Handler{
		agent:     agent,
		memory:    memory,
		config:    config,
		limiter:   limiter,
		metrics:   metrics.NewCollector(),
		apiKey:    apiKey,
		startedAt: time.Now(),
		streams:   map[string]<-chan ChatEvent{},
		sessions:  map[string]ChatRequest{},
		tools: []map[string]any{
			{"name": "read_file", "modes": []string{"all"}, "permission_level": "read"},
			{"name": "write_file", "modes": []string{"coding"}, "permission_level": "write"},
			{"name": "terminal", "modes": []string{"coding"}, "permission_level": "execute"},
		},
	}
}

// WithSubagents attaches a subagent client so subagent endpoints are served.
func (h *Handler) WithSubagents(subagents SubagentClient) *Handler {
	h.subagents = subagents
	return h
}

// Routes returns all REST routes with auth and rate limiting middleware.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/chat", h.handleChat)
	mux.HandleFunc("GET /api/chat/{id}/stream", h.handleChatStream)
	mux.HandleFunc("POST /api/chat/{id}/stream", h.handleChatNDJSONStream)
	mux.HandleFunc("POST /api/chat/{id}/confirm", h.handleConfirm)
	mux.HandleFunc("POST /api/mode", h.handleMode)
	mux.HandleFunc("POST /api/subagents/spawn", h.handleSubagentSpawn)
	mux.HandleFunc("POST /api/subagents/collect", h.handleSubagentCollect)
	mux.HandleFunc("GET /api/subagents/status", h.handleSubagentStatus)
	mux.HandleFunc("GET /api/metrics", h.handleMetrics)
	mux.HandleFunc("GET /api/memory", h.handleMemoryGet)
	mux.HandleFunc("POST /api/memory", h.handleMemorySet)
	mux.HandleFunc("DELETE /api/memory/{id}", h.handleMemoryDelete)
	mux.HandleFunc("GET /api/tools", h.handleTools)
	mux.HandleFunc("GET /api/sessions", h.handleSessions)
	mux.HandleFunc("GET /api/sessions/{id}", h.handleSessionDetail)
	mux.HandleFunc("GET /api/config", h.handleConfigGet)
	mux.HandleFunc("PUT /api/config", h.handleConfigSet)
	mux.HandleFunc("GET /api/audit", h.handleAudit)
	mux.HandleFunc("GET /api/health", h.handleHealth)
	return h.cors(auth.Middleware(h.apiKey, h.rateLimit(h.requestLog(h.metricsMiddleware(mux)))))
}

func (h *Handler) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Khaos-Key")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.limiter != nil && !h.limiter.Allow() {
			writeError(w, http.StatusTooManyRequests, "rate limited")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(recorder, r)
		durationMs := float64(time.Since(start).Microseconds()) / 1000.0
		log.Printf("%s %s %d %.1fms", r.Method, r.URL.Path, recorder.status, durationMs)
	})
}

func (h *Handler) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.metrics == nil {
			next.ServeHTTP(w, r)
			return
		}
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		h.metrics.IncrActive()
		defer h.metrics.DecrActive()
		next.ServeHTTP(recorder, r)
		var reqErr error
		if recorder.status >= http.StatusBadRequest {
			reqErr = fmt.Errorf("status %d", recorder.status)
		}
		route := r.Pattern
		if route == "" {
			route = r.URL.Path
		}
		h.metrics.RecordRequest(route, r.Method, time.Since(start), reqErr)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (h *Handler) handleChat(w http.ResponseWriter, r *http.Request) {
	var req ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Message == "" {
		writeError(w, http.StatusBadRequest, "message is required")
		return
	}
	if req.SessionID == "" {
		req.SessionID = fmt.Sprintf("session-%d", time.Now().UnixNano())
	}
	stream, err := h.agent.Chat(context.Background(), req)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	h.mu.Lock()
	h.streams[req.SessionID] = stream
	h.sessions[req.SessionID] = req
	h.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"session_id": req.SessionID})
}

func (h *Handler) handleChatStream(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	h.mu.Lock()
	stream := h.streams[sessionID]
	h.mu.Unlock()
	if stream == nil {
		writeError(w, http.StatusNotFound, "session stream not found")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	flusher, _ := w.(http.Flusher)
	for event := range stream {
		payload, _ := json.Marshal(event.Data)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Event, payload)
		if flusher != nil {
			flusher.Flush()
		}
	}
}

func (h *Handler) handleChatNDJSONStream(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	if sessionID == "" || sessionID == "new" {
		sessionID = fmt.Sprintf("session-%d", time.Now().UnixNano())
	}
	var req ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Message == "" {
		writeError(w, http.StatusBadRequest, "message is required")
		return
	}
	req.SessionID = sessionID
	stream, err := h.agent.Chat(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	encoder := json.NewEncoder(w)
	for event := range stream {
		if err := encoder.Encode(event); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

func (h *Handler) handleConfirm(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ToolCallID string `json:"tool_call_id"`
		Approved   bool   `json:"approved"`
		Remember   bool   `json:"remember"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if err := h.agent.ConfirmPermission(r.Context(), r.PathValue("id"), body.ToolCallID, body.Approved, body.Remember); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *Handler) handleMode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SessionID  string `json:"session_id"`
		TargetMode string `json:"target_mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	mode, err := h.agent.SwitchMode(r.Context(), body.SessionID, body.TargetMode)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"current_mode": mode})
}

func (h *Handler) handleSubagentSpawn(w http.ResponseWriter, r *http.Request) {
	if h.subagents == nil {
		writeError(w, http.StatusNotImplemented, "subagents not configured")
		return
	}
	var body struct {
		Goal    string   `json:"goal"`
		Context string   `json:"context"`
		Tools   []string `json:"tools"`
		Timeout int      `json:"timeout"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	result, err := h.subagents.Spawn(r.Context(), body.Goal, body.Context, body.Tools, body.Timeout)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) handleSubagentCollect(w http.ResponseWriter, r *http.Request) {
	if h.subagents == nil {
		writeError(w, http.StatusNotImplemented, "subagents not configured")
		return
	}
	result, err := h.subagents.CollectResults(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) handleSubagentStatus(w http.ResponseWriter, r *http.Request) {
	if h.subagents == nil {
		writeError(w, http.StatusNotImplemented, "subagents not configured")
		return
	}
	result, err := h.subagents.Status(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) handleMemoryGet(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	scope := query.Get("scope")
	if scope == "" {
		scope = "global"
	}
	topK, _ := strconv.Atoi(query.Get("top_k"))
	if topK <= 0 {
		topK = 5
	}
	if query.Get("query") != "" {
		memories, err := h.memory.Search(r.Context(), scope, query.Get("query"), topK)
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, memories)
		return
	}
	memory, err := h.memory.Get(r.Context(), scope, query.Get("key"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, memory)
}

func (h *Handler) handleMemorySet(w http.ResponseWriter, r *http.Request) {
	var memory Memory
	if err := json.NewDecoder(r.Body).Decode(&memory); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	stored, err := h.memory.Set(r.Context(), memory)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": stored.ID})
}

func (h *Handler) handleMemoryDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := h.memory.Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *Handler) handleTools(w http.ResponseWriter, r *http.Request) {
	mode := r.URL.Query().Get("mode")
	if mode == "" {
		writeJSON(w, http.StatusOK, h.tools)
		return
	}
	filtered := []map[string]any{}
	for _, tool := range h.tools {
		modes, _ := tool["modes"].([]string)
		for _, candidate := range modes {
			if candidate == "all" || candidate == mode {
				filtered = append(filtered, tool)
				break
			}
		}
	}
	writeJSON(w, http.StatusOK, filtered)
}

func (h *Handler) handleSessions(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	sessions := []ChatRequest{}
	for _, session := range h.sessions {
		sessions = append(sessions, session)
	}
	writeJSON(w, http.StatusOK, sessions)
}

func (h *Handler) handleSessionDetail(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	session, ok := h.sessions[r.PathValue("id")]
	if !ok {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"session": session, "messages": []any{}})
}

func (h *Handler) handleConfigGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.config.Get())
}

func (h *Handler) handleConfigSet(w http.ResponseWriter, r *http.Request) {
	var cfg map[string]any
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	h.config.Set(cfg)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *Handler) handleAudit(w http.ResponseWriter, r *http.Request) {
	if h.audit == nil {
		writeJSON(w, http.StatusOK, []AuditEntry{})
		return
	}
	query := r.URL.Query()
	limit, _ := strconv.Atoi(query.Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	entries, err := h.audit.Query(
		r.Context(),
		query.Get("action"),
		query.Get("result"),
		query.Get("since"),
		query.Get("until"),
		limit,
	)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if entries == nil {
		entries = []AuditEntry{}
	}
	writeJSON(w, http.StatusOK, entries)
}

func (h *Handler) handleMetrics(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.metrics.Snapshot())
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"uptime": int(time.Since(h.startedAt).Seconds()),
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// MemoryMap is an in-memory MemoryClient used by the gateway binary and tests.
type MemoryMap struct {
	mu     sync.Mutex
	nextID int64
	items  map[int64]Memory
}

// NewMemoryMap creates a memory map.
func NewMemoryMap() *MemoryMap {
	return &MemoryMap{nextID: 1, items: map[int64]Memory{}}
}

func (m *MemoryMap) Get(ctx context.Context, scope string, key string) (Memory, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, memory := range m.items {
		if memory.Scope == scope && memory.Key == key {
			return memory, nil
		}
	}
	return Memory{}, errors.New("memory not found")
}

func (m *MemoryMap) Set(ctx context.Context, memory Memory) (Memory, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if memory.ID == 0 {
		memory.ID = m.nextID
		m.nextID++
	}
	m.items[memory.ID] = memory
	return memory, nil
}

func (m *MemoryMap) Delete(ctx context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.items, id)
	return nil
}

func (m *MemoryMap) Search(ctx context.Context, scope string, query string, topK int) ([]Memory, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	results := []Memory{}
	for _, memory := range m.items {
		if (scope == "" || memory.Scope == scope) && (query == "" || strings.Contains(memory.Key, query) || strings.Contains(memory.Value, query)) {
			results = append(results, memory)
			if len(results) >= topK {
				break
			}
		}
	}
	return results, nil
}

// MapConfig is an in-memory config store.
type MapConfig struct {
	mu    sync.Mutex
	value map[string]any
}

func NewMapConfig(value map[string]any) *MapConfig {
	return &MapConfig{value: value}
}

func (c *MapConfig) Get() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	copy := map[string]any{}
	for k, v := range c.value {
		copy[k] = v
	}
	return copy
}

func (c *MapConfig) Set(value map[string]any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.value = value
}
