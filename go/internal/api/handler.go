package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
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
	agent                AgentClient
	memory               MemoryClient
	audit                AuditClient
	subagents            SubagentClient
	tasks                TaskClient
	config               ConfigStore
	authenticatedLimiter *rate.KeyedBuckets
	webhookLimiter       *rate.KeyedBuckets
	healthLimiter        *rate.TokenBucket
	metrics              *metrics.Collector
	apiKey               string
	allowedHosts         map[string]struct{}
	allowedOrigins       map[string]struct{}
	startedAt            time.Time
	mu                   sync.Mutex
	streams              map[string]<-chan ChatEvent
	sessions             map[string]ChatRequest
	sessionOwners        map[string]string
	taskOwners           map[string]string
	tools                []map[string]any
}

const (
	protocolVersion           = "1"
	maxRequestBodyBytes int64 = 1 << 20
	maxWebhookBodyBytes int64 = 2 << 20
)

var signatureAuthenticatedWebhookPlatforms = map[string]struct{}{
	"discord":  {},
	"slack":    {},
	"telegram": {},
	"wechat":   {},
}

// WithTasks attaches the persistent coding task service.
func (h *Handler) WithTasks(tasks TaskClient) *Handler { h.tasks = tasks; return h }

// WithAudit attaches an audit client so GET /api/audit is served.
func (h *Handler) WithAudit(audit AuditClient) *Handler {
	h.audit = audit
	return h
}

// NewHandler creates an API handler.
func NewHandler(agent AgentClient, memory MemoryClient, config ConfigStore, apiKey string, limiter *rate.TokenBucket) *Handler {
	ratePerMinute, burst := 60, 10
	if limiter != nil {
		ratePerMinute, burst = limiter.Config()
	}
	return &Handler{
		agent:                agent,
		memory:               memory,
		config:               config,
		authenticatedLimiter: rate.NewKeyedBuckets(ratePerMinute, burst, 4096, 10*time.Minute),
		webhookLimiter:       rate.NewKeyedBuckets(ratePerMinute, burst, 4096, 10*time.Minute),
		healthLimiter:        limiter,
		metrics:              metrics.NewCollector(),
		apiKey:               apiKey,
		allowedHosts: map[string]struct{}{
			"localhost": {}, "127.0.0.1": {}, "::1": {},
		},
		allowedOrigins: map[string]struct{}{},
		startedAt:      time.Now(),
		streams:        map[string]<-chan ChatEvent{},
		sessions:       map[string]ChatRequest{},
		sessionOwners:  map[string]string{},
		taskOwners:     map[string]string{},
		tools: []map[string]any{
			{"name": "read_file", "modes": []string{"all"}, "permission_level": "read"},
			{"name": "write_file", "modes": []string{"coding"}, "permission_level": "write"},
			{"name": "terminal", "modes": []string{"coding"}, "permission_level": "execute"},
		},
	}
}

// WithAllowedHosts replaces the HTTP Host allowlist used to prevent DNS
// rebinding. Values are host names or IP literals; ports are ignored.
func (h *Handler) WithAllowedHosts(hosts ...string) *Handler {
	h.allowedHosts = map[string]struct{}{}
	for _, host := range hosts {
		if normalized := normalizeHost(host); normalized != "" {
			h.allowedHosts[normalized] = struct{}{}
		}
	}
	return h
}

// WithAllowedOrigins enables browser access for exact http(s) origins. The
// default is an empty allowlist and therefore emits no CORS headers.
func (h *Handler) WithAllowedOrigins(origins ...string) *Handler {
	h.allowedOrigins = map[string]struct{}{}
	for _, origin := range origins {
		if normalized := normalizeOrigin(origin); normalized != "" {
			h.allowedOrigins[normalized] = struct{}{}
		}
	}
	return h
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
	mux.HandleFunc("POST /api/webhook/{platform}", h.handleWebhook)
	mux.HandleFunc("GET /api/channels", h.handleChannelsList)
	mux.HandleFunc("GET /api/channels/health", h.handleChannelsList)
	mux.HandleFunc("POST /api/channels/{id}/enable", h.handleChannelEnable)
	mux.HandleFunc("POST /api/channels/{id}/disable", h.handleChannelDisable)
	mux.HandleFunc("POST /v1/tasks", h.handleCreateTask)
	mux.HandleFunc("GET /v1/tasks", h.handleListTasks)
	mux.HandleFunc("GET /v1/tasks/{id}", h.handleGetTask)
	mux.HandleFunc("POST /v1/tasks/{id}/cancel", h.handleCancelTask)
	mux.HandleFunc("POST /v1/tasks/{id}/approve", h.handleApproveTask)
	mux.HandleFunc("POST /v1/tasks/{id}/reject", h.handleRejectTask)
	mux.HandleFunc("GET /v1/tasks/{id}/events", h.handleTaskEvents)
	mux.HandleFunc("GET /v1/tasks/{id}/artifacts", h.handleTaskArtifacts)
	common := h.requestLog(h.metricsMiddleware(mux))
	health := h.rateLimit(h.healthLimiter, common)
	webhookIngress := h.keyedRateLimit(
		h.webhookLimiter, webhookSourceIdentity, common,
	)
	authenticated := h.keyedRateLimit(
		h.authenticatedLimiter, authenticatedPrincipalIdentity, common,
	)
	secured := auth.Middleware(h.apiKey, authenticated)
	root := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health is intentionally the only anonymous Khaos endpoint. Platform
		// webhooks use their own signature authentication in the Python service.
		if r.URL.Path == "/api/health" {
			health.ServeHTTP(w, r)
			return
		}
		// Only platforms with an implemented signature protocol may bypass the
		// Gateway API key. Generic and unknown webhook paths remain authenticated.
		if isSignatureAuthenticatedWebhookPath(r.URL.Path) {
			webhookIngress.ServeHTTP(w, r)
			return
		}
		secured.ServeHTTP(w, r)
	})
	return h.hostGuard(h.originPolicy(h.protocol(h.limitRequestBody(root))))
}

func isSignatureAuthenticatedWebhookPath(path string) bool {
	const prefix = "/api/webhook/"
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	platform := strings.TrimPrefix(path, prefix)
	if platform == "" || strings.Contains(platform, "/") {
		return false
	}
	_, ok := signatureAuthenticatedWebhookPlatforms[platform]
	return ok
}

func (h *Handler) handleCreateTask(w http.ResponseWriter, r *http.Request) {
	if h.tasks == nil {
		writeError(w, http.StatusServiceUnavailable, "task service not available")
		return
	}
	principalID, authenticated := auth.PrincipalFromContext(r.Context())
	if !authenticated {
		writeError(w, http.StatusUnauthorized, "authenticated principal required")
		return
	}
	var request struct {
		Goal string `json:"goal"`
	}
	if decodeJSON(r, &request) != nil || strings.TrimSpace(request.Goal) == "" {
		writeError(w, http.StatusBadRequest, "goal is required")
		return
	}
	result, err := h.tasks.CreateTask(r.Context(), principalID, request.Goal)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	id, valid := result["id"].(string)
	if !valid || id == "" {
		writeError(w, http.StatusBadGateway, "task service returned no task id")
		return
	}
	h.mu.Lock()
	h.taskOwners[id] = principalID
	h.mu.Unlock()
	writeJSON(w, http.StatusCreated, result)
}

func (h *Handler) handleListTasks(w http.ResponseWriter, r *http.Request) {
	if h.tasks == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	principalID, authenticated := auth.PrincipalFromContext(r.Context())
	if !authenticated {
		writeError(w, http.StatusUnauthorized, "authenticated principal required")
		return
	}
	result, err := h.tasks.ListTasks(r.Context(), principalID, r.URL.Query().Get("active") == "true")
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	// C-1-1: Python's TaskService now scopes by ctx.principal_id, so
	// result already contains only the caller's tasks.  The in-memory
	// taskOwners filter is retained as defense-in-depth until C-1-2
	// deletes the Go-side ownership map entirely.
	filtered := make([]map[string]any, 0, len(result))
	h.mu.Lock()
	for _, task := range result {
		id, _ := task["id"].(string)
		if h.taskOwners[id] == principalID {
			filtered = append(filtered, task)
		}
	}
	h.mu.Unlock()
	result = filtered
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) handleGetTask(w http.ResponseWriter, r *http.Request) {
	if h.tasks == nil {
		writeError(w, http.StatusServiceUnavailable, "task service not available")
		return
	}
	if !h.authorizeTask(w, r) {
		return
	}
	principalID, _ := auth.PrincipalFromContext(r.Context())
	result, err := h.tasks.GetTask(r.Context(), principalID, r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) handleCancelTask(w http.ResponseWriter, r *http.Request) {
	if h.tasks == nil {
		writeError(w, http.StatusServiceUnavailable, "task service not available")
		return
	}
	if !h.authorizeTask(w, r) {
		return
	}
	principalID, _ := auth.PrincipalFromContext(r.Context())
	h.changeTask(w, r, "cancelled", func(ctx context.Context, id string) (TransitionResult, error) {
		return h.tasks.CancelTask(ctx, principalID, id)
	})
}
func (h *Handler) handleApproveTask(w http.ResponseWriter, r *http.Request) {
	if h.tasks == nil {
		writeError(w, http.StatusServiceUnavailable, "task service not available")
		return
	}
	if !h.authorizeTask(w, r) {
		return
	}
	h.changeTaskApproval(w, r, "approved", h.tasks.ApproveTask)
}
func (h *Handler) handleRejectTask(w http.ResponseWriter, r *http.Request) {
	if h.tasks == nil {
		writeError(w, http.StatusServiceUnavailable, "task service not available")
		return
	}
	if !h.authorizeTask(w, r) {
		return
	}
	h.changeTaskApproval(w, r, "rejected", h.tasks.RejectTask)
}

func (h *Handler) changeTaskApproval(w http.ResponseWriter, r *http.Request, status string, action func(context.Context, string, string, string, string) (TransitionResult, error)) {
	principalID, authenticated := auth.PrincipalFromContext(r.Context())
	if !authenticated {
		writeError(w, http.StatusUnauthorized, "authenticated principal required")
		return
	}
	var body struct {
		SessionID     string `json:"session_id"`
		BindingDigest string `json:"binding_digest"`
	}
	if decodeJSON(r, &body) != nil || body.SessionID == "" || body.BindingDigest == "" {
		writeError(w, http.StatusBadRequest, "session_id and binding_digest are required")
		return
	}
	result, err := action(r.Context(), r.PathValue("id"), principalID, body.SessionID, body.BindingDigest)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if result == TransitionNotFound {
		writeError(w, http.StatusNotFound, "task not found")
		return
	}
	if result != TransitionUpdated {
		writeError(w, http.StatusConflict, "invalid task transition or approval binding")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": status, "task_id": r.PathValue("id")})
}
func (h *Handler) changeTask(w http.ResponseWriter, r *http.Request, status string, action func(context.Context, string) (TransitionResult, error)) {
	if h.tasks == nil {
		writeError(w, http.StatusServiceUnavailable, "task service not available")
		return
	}
	id := r.PathValue("id")
	result, err := action(r.Context(), id)
	if err != nil || result == TransitionNotFound || result == TransitionInvalid {
		if result == TransitionNotFound {
			writeError(w, http.StatusNotFound, "task not found")
			return
		}
		if result == TransitionInvalid {
			writeError(w, http.StatusConflict, "invalid task transition")
			return
		}
		if err == nil {
			writeError(w, http.StatusConflict, "invalid task transition")
			return
		}
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": status, "task_id": id})
}

func (h *Handler) handleTaskEvents(w http.ResponseWriter, r *http.Request) {
	if h.tasks == nil {
		writeError(w, http.StatusServiceUnavailable, "task service not available")
		return
	}
	if !h.authorizeTask(w, r) {
		return
	}
	principalID, _ := auth.PrincipalFromContext(r.Context())
	events, err := h.tasks.TaskEvents(r.Context(), principalID, r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}
	lastSequence, _ := strconv.ParseUint(r.Header.Get("Last-Event-ID"), 10, 64)
	for {
		select {
		case <-r.Context().Done():
			return
		case event, open := <-events:
			if !open {
				return
			}
			sequence := eventSequence(event["sequence"])
			if sequence > 0 && sequence <= lastSequence {
				continue
			}
			data, _ := json.Marshal(event)
			if sequence > 0 {
				fmt.Fprintf(w, "id: %d\n", sequence)
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (h *Handler) handleTaskArtifacts(w http.ResponseWriter, r *http.Request) {
	if h.tasks == nil {
		writeError(w, http.StatusServiceUnavailable, "task service not available")
		return
	}
	if !h.authorizeTask(w, r) {
		return
	}
	principalID, _ := auth.PrincipalFromContext(r.Context())
	result, err := h.tasks.TaskArtifacts(r.Context(), principalID, r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) channelClient(w http.ResponseWriter) (ChannelClient, bool) {
	client, ok := h.agent.(ChannelClient)
	if !ok {
		writeError(w, http.StatusNotImplemented, "channel service not configured")
	}
	return client, ok
}

func (h *Handler) handleWebhook(w http.ResponseWriter, r *http.Request) {
	client, ok := h.channelClient(w)
	if !ok {
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid webhook body")
		return
	}
	headers := make(map[string]string, len(r.Header))
	for key, values := range r.Header {
		if len(values) > 0 {
			headers[strings.ToLower(key)] = values[0]
		}
	}
	query := make(map[string]string, len(r.URL.Query()))
	for key, values := range r.URL.Query() {
		if len(values) > 0 {
			query[strings.ToLower(key)] = values[0]
		}
	}
	// C-1-1: signature-authenticated webhook ingress bypasses the
	// API-key middleware, so there is no authenticated principal.
	// Pass ``""`` so Python's AgentService.HandleWebhook treats the
	// call as unauthenticated platform ingress (same behavior as
	// before, but explicit instead of defaulting to ``"gateway"``).
	response, err := client.HandleWebhook(r.Context(), "", WebhookRequest{Platform: r.PathValue("platform"), ChannelID: r.URL.Query().Get("channel_id"), Headers: headers, Query: query, Body: json.RawMessage(body)})
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	status := http.StatusOK
	if response.Status == "rate_limited" {
		status = http.StatusTooManyRequests
	} else if response.Status != "ok" {
		status = http.StatusBadRequest
	}
	writeJSON(w, status, response)
}

func (h *Handler) handleChannelsList(w http.ResponseWriter, r *http.Request) {
	client, ok := h.channelClient(w)
	if !ok {
		return
	}
	principalID, _ := auth.PrincipalFromContext(r.Context())
	channels, err := client.ListChannels(r.Context(), principalID)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"channels": channels})
}

func (h *Handler) handleChannelEnable(w http.ResponseWriter, r *http.Request) {
	h.setChannelEnabled(w, r, true)
}

func (h *Handler) handleChannelDisable(w http.ResponseWriter, r *http.Request) {
	h.setChannelEnabled(w, r, false)
}

func (h *Handler) setChannelEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	client, ok := h.channelClient(w)
	if !ok {
		return
	}
	principalID, _ := auth.PrincipalFromContext(r.Context())
	if err := client.SetChannelEnabled(r.Context(), principalID, r.PathValue("id"), enabled); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) originPolicy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}
		normalized := normalizeOrigin(origin)
		if _, allowed := h.allowedOrigins[normalized]; !allowed || normalized == "" {
			writeError(w, http.StatusForbidden, "origin is not allowed")
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", normalized)
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Khaos-Key")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) hostGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := normalizeHost(r.Host)
		if host == "" {
			writeError(w, http.StatusBadRequest, "invalid Host header")
			return
		}
		if _, allowed := h.allowedHosts[host]; !allowed {
			writeError(w, http.StatusForbidden, "Host header is not allowed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func normalizeHost(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	} else if strings.Count(value, ":") == 1 {
		return ""
	}
	value = strings.TrimSuffix(strings.Trim(value, "[]"), ".")
	return value
}

func normalizeOrigin(value string) string {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") ||
		parsed.Host == "" || parsed.User != nil || parsed.Path != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return ""
	}
	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host)
}

func (h *Handler) protocol(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Khaos-Protocol-Version", protocolVersion)
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) limitRequestBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := maxRequestBodyBytes
		if strings.HasPrefix(r.URL.Path, "/api/webhook/") {
			limit = maxWebhookBodyBytes
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) authorizeSession(w http.ResponseWriter, r *http.Request, sessionID string) bool {
	principalID, authenticated := auth.PrincipalFromContext(r.Context())
	if !authenticated {
		writeError(w, http.StatusUnauthorized, "authenticated principal required")
		return false
	}
	h.mu.Lock()
	owner := h.sessionOwners[sessionID]
	h.mu.Unlock()
	if owner == "" || owner != principalID {
		writeError(w, http.StatusForbidden, "session is not owned by authenticated principal")
		return false
	}
	return true
}

func (h *Handler) authorizeTask(w http.ResponseWriter, r *http.Request) bool {
	principalID, authenticated := auth.PrincipalFromContext(r.Context())
	if !authenticated {
		writeError(w, http.StatusUnauthorized, "authenticated principal required")
		return false
	}
	h.mu.Lock()
	owner := h.taskOwners[r.PathValue("id")]
	h.mu.Unlock()
	if owner == "" || owner != principalID {
		writeError(w, http.StatusForbidden, "task is not owned by authenticated principal")
		return false
	}
	return true
}

func (h *Handler) rateLimit(limiter *rate.TokenBucket, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if limiter != nil && !limiter.Allow() {
			writeError(w, http.StatusTooManyRequests, "rate limited")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) keyedRateLimit(
	limiter *rate.KeyedBuckets,
	identity func(*http.Request) string,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if limiter != nil && !limiter.Allow(identity(r)) {
			writeError(w, http.StatusTooManyRequests, "rate limited")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func authenticatedPrincipalIdentity(r *http.Request) string {
	principal, authenticated := auth.PrincipalFromContext(r.Context())
	if !authenticated {
		return "unauthenticated"
	}
	return principal
}

func webhookSourceIdentity(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
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
		h.metrics.RecordRequest(r.URL.Path, r.Method, time.Since(start), reqErr)
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
	if err := decodeJSON(r, &req); err != nil {
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
	principalID, authenticated := auth.PrincipalFromContext(r.Context())
	if !authenticated {
		writeError(w, http.StatusUnauthorized, "authenticated principal required")
		return
	}
	req.PrincipalID = principalID
	h.mu.Lock()
	owner := h.sessionOwners[req.SessionID]
	h.mu.Unlock()
	if owner != "" && owner != req.PrincipalID {
		writeError(w, http.StatusForbidden, "session belongs to another principal")
		return
	}
	stream, err := h.agent.Chat(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	h.mu.Lock()
	h.streams[req.SessionID] = stream
	h.sessions[req.SessionID] = req
	h.sessionOwners[req.SessionID] = req.PrincipalID
	h.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"session_id": req.SessionID})
}

func (h *Handler) handleChatStream(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	if !h.authorizeSession(w, r, sessionID) {
		return
	}
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
	for {
		select {
		case <-r.Context().Done():
			return
		case event, open := <-stream:
			if !open {
				return
			}
			payload, _ := json.Marshal(event.Data)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Event, payload)
			if flusher != nil {
				flusher.Flush()
			}
		}
	}
}

func (h *Handler) handleChatNDJSONStream(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	if sessionID == "" || sessionID == "new" {
		sessionID = fmt.Sprintf("session-%d", time.Now().UnixNano())
	}
	var req ChatRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Message == "" {
		writeError(w, http.StatusBadRequest, "message is required")
		return
	}
	req.SessionID = sessionID
	principalID, authenticated := auth.PrincipalFromContext(r.Context())
	if !authenticated {
		writeError(w, http.StatusUnauthorized, "authenticated principal required")
		return
	}
	req.PrincipalID = principalID
	h.mu.Lock()
	owner := h.sessionOwners[sessionID]
	h.mu.Unlock()
	if owner != "" && owner != req.PrincipalID {
		writeError(w, http.StatusForbidden, "session belongs to another principal")
		return
	}
	stream, err := h.agent.Chat(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	h.mu.Lock()
	h.sessionOwners[sessionID] = req.PrincipalID
	h.sessions[sessionID] = req
	h.mu.Unlock()
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	encoder := json.NewEncoder(w)
	for {
		select {
		case <-r.Context().Done():
			return
		case event, open := <-stream:
			if !open {
				return
			}
			if err := encoder.Encode(event); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
	}
}

func (h *Handler) handleConfirm(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ToolCallID    string `json:"tool_call_id"`
		Approved      bool   `json:"approved"`
		Remember      bool   `json:"remember"`
		BindingDigest string `json:"binding_digest"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	principalID, authenticated := auth.PrincipalFromContext(r.Context())
	if !authenticated {
		writeError(w, http.StatusUnauthorized, "authenticated principal required")
		return
	}
	if body.ToolCallID == "" || body.BindingDigest == "" {
		writeError(w, http.StatusBadRequest, "tool_call_id and binding_digest are required")
		return
	}
	if !h.authorizeSession(w, r, r.PathValue("id")) {
		return
	}
	if err := h.agent.ConfirmPermission(r.Context(), principalID, r.PathValue("id"), body.ToolCallID, body.BindingDigest, body.Approved, body.Remember); err != nil {
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
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if !h.authorizeSession(w, r, body.SessionID) {
		return
	}
	principalID, _ := auth.PrincipalFromContext(r.Context())
	mode, err := h.agent.SwitchMode(r.Context(), principalID, body.SessionID, body.TargetMode)
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
	principalID, authenticated := auth.PrincipalFromContext(r.Context())
	if !authenticated {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var body struct {
		Goal    string   `json:"goal"`
		Context string   `json:"context"`
		Tools   []string `json:"tools"`
		Timeout int      `json:"timeout"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	result, err := h.subagents.Spawn(r.Context(), principalID, body.Goal, body.Context, body.Tools, body.Timeout)
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
	principalID, authenticated := auth.PrincipalFromContext(r.Context())
	if !authenticated {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	result, err := h.subagents.CollectResults(r.Context(), principalID)
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
	principalID, authenticated := auth.PrincipalFromContext(r.Context())
	if !authenticated {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	result, err := h.subagents.Status(r.Context(), principalID)
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
	if err := decodeJSON(r, &memory); err != nil {
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
	principalID, authenticated := auth.PrincipalFromContext(r.Context())
	for id, session := range h.sessions {
		if authenticated && h.sessionOwners[id] != principalID {
			continue
		}
		sessions = append(sessions, session)
	}
	writeJSON(w, http.StatusOK, sessions)
}

func (h *Handler) handleSessionDetail(w http.ResponseWriter, r *http.Request) {
	if !h.authorizeSession(w, r, r.PathValue("id")) {
		return
	}
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
	if err := decodeJSON(r, &cfg); err != nil {
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
	principalID, _ := auth.PrincipalFromContext(r.Context())
	entries, err := h.audit.Query(
		r.Context(),
		principalID,
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

func decodeJSON(r *http.Request, target any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func eventSequence(value any) uint64 {
	switch sequence := value.(type) {
	case int:
		if sequence > 0 {
			return uint64(sequence)
		}
	case int64:
		if sequence > 0 {
			return uint64(sequence)
		}
	case float64:
		if sequence > 0 {
			return uint64(sequence)
		}
	case json.Number:
		parsed, _ := strconv.ParseUint(sequence.String(), 10, 64)
		return parsed
	}
	return 0
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
