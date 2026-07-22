package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"khaos/go/internal/api"
	"khaos/go/internal/platform"
	"khaos/go/internal/rate"
)

type mockAgentClient struct{}

func (m mockAgentClient) Chat(ctx context.Context, req api.ChatRequest) (<-chan api.ChatEvent, error) {
	ch := make(chan api.ChatEvent, 4)
	go func() {
		defer close(ch)
		ch <- api.ChatEvent{Event: "message", Data: map[string]any{"role": "assistant", "content": "Khaos gateway mock response.", "token_count": 4}}
		ch <- api.ChatEvent{Event: "done", Data: map[string]any{"total_tokens": 4, "turns": 1, "duration_ms": 1}}
	}()
	return ch, nil
}

func (m mockAgentClient) ChatEvents(_ context.Context, _ string, _ string, after uint64) (<-chan api.ChatEvent, error) {
	ch := make(chan api.ChatEvent, 2)
	if after < 1 {
		ch <- api.ChatEvent{Sequence: 1, Event: "message", Data: map[string]any{"role": "assistant", "content": "Khaos gateway mock response.", "token_count": 4}}
	}
	if after < 2 {
		ch <- api.ChatEvent{Sequence: 2, Event: "done", Data: map[string]any{"total_tokens": 4}}
	}
	close(ch)
	return ch, nil
}

func (m mockAgentClient) ConfirmPermission(ctx context.Context, principalID string, sessionID string, toolCallID string, bindingDigest string, approved bool, remember bool) error {
	return nil
}

func (m mockAgentClient) SwitchMode(ctx context.Context, principalID string, sessionID string, targetMode string) (string, error) {
	return targetMode, nil
}

func main() {
	defaultAPIKey := os.Getenv("KHAOS_API_KEY")
	defaultAPIKeyFile := os.Getenv("KHAOS_API_KEY_FILE")
	defaultAllowedOrigins := os.Getenv("KHAOS_CORS_ORIGINS")
	defaultAllowedHosts := os.Getenv("KHAOS_ALLOWED_HOSTS")
	defaultPythonAgent := os.Getenv("KHAOS_PYTHON_AGENT")
	if defaultPythonAgent == "" {
		defaultPythonAgent = fmt.Sprintf("/tmp/khaos-%d/agent.sock", os.Getuid())
	}
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	apiKey := flag.String("api-key", defaultAPIKey, "X-Khaos-Key value")
	apiKeyFile := flag.String("api-key-file", defaultAPIKeyFile, "path to the mode-0600 local gateway token")
	allowedOrigins := flag.String("cors-origins", defaultAllowedOrigins, "comma-separated exact browser origins")
	allowedHosts := flag.String("allowed-hosts", defaultAllowedHosts, "comma-separated HTTP Host names")
	pythonAddr := flag.String("python-agent", defaultPythonAgent, "Python AgentService Unix socket path")
	projectRoot := flag.String("project-root", os.Getenv("KHAOS_PROJECT_ROOT"), "project root directory (used to compute project_id for drift detection; REQUIRED in production, rejected if empty)")
	mockAgent := flag.Bool("mock-agent", false, "use in-process mock agent")
	enableSubagents := flag.Bool("subagents", false, "enable subagent proxy")
	flag.Parse()
	pythonCapability := ""
	if !*mockAgent {
		loadedCapability, capabilityErr := loadPythonCapability()
		if capabilityErr != nil {
			log.Fatal(capabilityErr)
		}
		pythonCapability = loadedCapability
	}
	resolvedKey, tokenPath, err := loadOrCreateAPIKey(*apiKey, *apiKeyFile)
	if err != nil {
		log.Fatal(err)
	}
	if err := validateListenConfig(*addr, resolvedKey); err != nil {
		log.Fatal(err)
	}

	// C-2-1 (CRITICAL fix): construct the FINAL PythonClient BEFORE
	// NewHandler so every interface (Chat/Confirm/SwitchMode/Audit/Tasks/
	// Subagents) shares the same client with project_id + policy_digest
	// stamped.  Previously NewHandler received a bare PythonClient (empty
	// ProjectID/PolicyDigest), and the later `agent = pc` only mutated
	// the local variable — handler.agent kept the bootstrap-less copy, so
	// /api/chat, ConfirmPermission and SwitchMode silently ran without
	// drift claims on every successful startup.
	//
	// Production mode (non-mock) is now fail-closed: empty --project-root,
	// project_id computation failure, or policy_digest bootstrap failure
	// all reject startup via log.Fatal.  Drift detection can no longer be
	// silently disabled.
	var agent api.AgentClient
	var pythonClient platform.PythonClient
	if *mockAgent {
		agent = mockAgentClient{}
	} else {
		initial := platform.PythonClient{
			Address:    *pythonAddr,
			Capability: pythonCapability,
		}
		resolved, resolveErr := resolvePythonClient(initial, *projectRoot, initial.BootstrapPolicyDigest)
		if resolveErr != nil {
			log.Fatal(resolveErr)
		}
		pythonClient = resolved
		log.Printf("project-id: %s", pythonClient.ProjectID)
		log.Printf("policy-digest: %s", pythonClient.PolicyDigest)
		agent = pythonClient
	}

	// C-2-2 (HIGH 6): the production Gateway no longer keeps an
	// in-process MemoryMap — REST /api/memory proxies Python's
	// per-principal MemoryService via the same pythonClient that
	// carries project_id + policy_digest drift claims.  The mock-agent
	// path (development only) still uses NewMemoryMap() so /api/memory
	// works without a Python backend.
	var memoryClient api.MemoryClient
	if *mockAgent {
		memoryClient = api.NewMemoryMap()
	} else {
		memoryClient = pythonClient
	}
	handler := api.NewHandler(
		agent,
		memoryClient,
		api.NewMapConfig(map[string]any{"started_at": time.Now().Format(time.RFC3339)}),
		resolvedKey,
		rate.NewTokenBucket(60, 10),
	)
	handler = handler.WithAllowedOrigins(splitCSV(*allowedOrigins)...)
	handler = handler.WithAllowedHosts(allowedHostnames(*addr, splitCSV(*allowedHosts))...)
	// When talking to a real Python agent, also forward audit queries. The mock
	// agent path leaves audit unconfigured (GET /api/audit returns []).
	// C-2-1: all interfaces receive the SAME pythonClient (which is also
	// `agent`) so Chat/Confirm/SwitchMode and Audit/Tasks/Subagents share
	// identical project_id + policy_digest claims.
	// C-2-3: SessionsService is also proxied through the same client so
	// ``GET /api/sessions`` reads from the durable ``sessions`` table
	// (principal-scoped) instead of the Go in-memory map.
	if !*mockAgent {
		handler = handler.WithAudit(pythonClient)
		handler = handler.WithTasks(pythonClient)
		handler = handler.WithSessions(pythonClient)
		if *enableSubagents {
			handler = handler.WithSubagents(pythonClient)
		}
	}
	log.Printf("Khaos gateway listening on %s", *addr)
	if tokenPath != "" {
		log.Printf("Gateway token loaded from protected file %s", tokenPath)
	}
	if *enableSubagents {
		log.Printf("Subagent proxy enabled (Python agent: %s)", *pythonAddr)
	}
	server := &http.Server{
		Addr:              *addr,
		Handler:           handler.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	log.Fatal(server.ListenAndServe())
}

func loadPythonCapability() (string, error) {
	var content []byte
	if rawFD := strings.TrimSpace(os.Getenv("KHAOS_PYTHON_CAPABILITY_FD")); rawFD != "" {
		fd, err := strconv.Atoi(rawFD)
		if err != nil || fd < 3 {
			return "", errors.New("invalid inherited Python capability FD")
		}
		file := os.NewFile(uintptr(fd), "khaos-python-capability")
		if file == nil {
			return "", errors.New("inherited Python capability FD is unavailable")
		}
		defer file.Close()
		content, err = io.ReadAll(io.LimitReader(file, 4097))
		if err != nil {
			return "", fmt.Errorf("read inherited Python capability: %w", err)
		}
		_ = os.Unsetenv("KHAOS_PYTHON_CAPABILITY_FD")
	} else if path := strings.TrimSpace(os.Getenv("KHAOS_PYTHON_CAPABILITY_FILE")); path != "" {
		entry, err := os.Lstat(path)
		if err != nil || !entry.Mode().IsRegular() || entry.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("Python capability file must be a regular file")
		}
		containerSecret := strings.HasPrefix(filepath.Clean(path), "/run/secrets/")
		if (containerSecret && entry.Mode().Perm()&0o222 != 0) || (!containerSecret && entry.Mode().Perm()&0o077 != 0) {
			return "", errors.New("Python capability file permissions are unsafe")
		}
		file, err := os.Open(path)
		if err != nil {
			return "", err
		}
		opened, statErr := file.Stat()
		if statErr != nil || !os.SameFile(entry, opened) {
			file.Close()
			return "", errors.New("Python capability file identity changed")
		}
		content, err = io.ReadAll(io.LimitReader(file, 4097))
		openedInfo := opened
		file.Close()
		if err != nil {
			return "", err
		}
		finalInfo, finalErr := os.Lstat(path)
		if finalErr != nil || !os.SameFile(openedInfo, finalInfo) {
			return "", errors.New("Python capability file identity changed")
		}
	} else if os.Getenv("KHAOS_ALLOW_LEGACY_CAPABILITY_ENV") == "1" {
		content = []byte(os.Getenv("KHAOS_PYTHON_CAPABILITY"))
	} else {
		return "", errors.New("Python capability requires an inherited FD or protected file")
	}
	if len(content) > 4096 {
		return "", errors.New("Python capability is too large")
	}
	capability := strings.TrimSpace(string(content))
	if len(capability) < 32 {
		return "", errors.New("Python capability must contain at least 32 characters")
	}
	return capability, nil
}

func validateListenConfig(addr, apiKey string) error {
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if apiKey == "" {
		return errors.New("refusing gateway listen without an authentication token")
	}
	if len(apiKey) < 32 {
		return errors.New("refusing gateway listen with an authentication token shorter than 32 characters")
	}
	return nil
}

func loadOrCreateAPIKey(configured, configuredPath string) (string, string, error) {
	if key := strings.TrimSpace(configured); key != "" {
		return key, "", nil
	}
	tokenPath := strings.TrimSpace(configuredPath)
	if tokenPath == "" {
		configDir, err := os.UserConfigDir()
		if err != nil {
			return "", "", fmt.Errorf("resolve user config directory: %w", err)
		}
		tokenPath = filepath.Join(configDir, "khaos", "gateway-token")
	}
	absolute, err := filepath.Abs(tokenPath)
	if err != nil {
		return "", "", fmt.Errorf("resolve gateway token path: %w", err)
	}
	if runtime.GOOS == "windows" {
		configRoot, rootErr := os.UserConfigDir()
		if rootErr != nil {
			return "", "", fmt.Errorf("resolve Windows user config directory: %w", rootErr)
		}
		privateRoot := filepath.Join(configRoot, "khaos")
		relative, relErr := filepath.Rel(privateRoot, absolute)
		if relErr != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return "", "", errors.New("Windows gateway token must be inside the current user config directory")
		}
	}
	if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
		return "", "", fmt.Errorf("create gateway token directory: %w", err)
	}
	directoryInfo, err := os.Lstat(filepath.Dir(absolute))
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 {
		return "", "", errors.New("gateway token parent must be a real directory")
	}
	if err := os.Chmod(filepath.Dir(absolute), 0o700); err != nil {
		return "", "", fmt.Errorf("protect gateway token directory: %w", err)
	}
	if key, err := readProtectedToken(absolute); err == nil {
		return key, absolute, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", "", err
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", "", fmt.Errorf("generate gateway token: %w", err)
	}
	key := base64.RawURLEncoding.EncodeToString(random)
	file, err := os.OpenFile(absolute, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		loaded, loadErr := readProtectedToken(absolute)
		return loaded, absolute, loadErr
	}
	if err != nil {
		return "", "", fmt.Errorf("create gateway token: %w", err)
	}
	var writeErr error
	if _, err := file.WriteString(key + "\n"); err != nil {
		writeErr = err
	} else if err := file.Sync(); err != nil {
		writeErr = err
	}
	if err := file.Close(); writeErr == nil {
		writeErr = err
	}
	if writeErr != nil {
		return "", "", fmt.Errorf("write gateway token: %w", writeErr)
	}
	return key, absolute, nil
}

func readProtectedToken(path string) (string, error) {
	entryInfo, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !entryInfo.Mode().IsRegular() || (runtime.GOOS != "windows" && entryInfo.Mode().Perm()&0o077 != 0) {
		return "", errors.New("gateway token must be a regular file inaccessible to group and others")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("read gateway token: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(entryInfo, openedInfo) {
		return "", errors.New("gateway token identity changed while opening")
	}
	content, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return "", fmt.Errorf("read gateway token: %w", err)
	}
	if len(content) > 4096 {
		return "", errors.New("gateway token file is too large")
	}
	finalInfo, err := os.Lstat(path)
	if err != nil || !os.SameFile(openedInfo, finalInfo) {
		return "", errors.New("gateway token identity changed while reading")
	}
	key := strings.TrimSpace(string(content))
	if len(key) < 32 {
		return "", errors.New("gateway token file contains a weak token")
	}
	return key, nil
}

func splitCSV(value string) []string {
	var values []string
	for _, item := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	return values
}

func allowedHostnames(addr string, configured []string) []string {
	if len(configured) != 0 {
		return configured
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	result := []string{host}
	ip := net.ParseIP(host)
	if host == "localhost" || (ip != nil && ip.IsLoopback()) {
		result = append(result, "localhost", "127.0.0.1", "::1")
	}
	return result
}

// digestBootstrapFunc fetches policy_digest from the Python agent via the
// Bootstrap.GetPolicyDigest startup handshake.  Extracted as a parameter
// so resolvePythonClient is unit-testable without a real Python socket.
type digestBootstrapFunc func(ctx context.Context) (string, error)

// resolvePythonClient constructs the final PythonClient with project_id
// and policy_digest stamped.  C-2-1 (CRITICAL fix): this MUST be called
// before NewHandler so every interface (Chat/Confirm/SwitchMode/Audit/
// Tasks/Subagents) shares the same client.
//
// Production mode is fail-closed:
//   - empty projectRoot rejects startup (no silent drift-detection disable)
//   - project_id computation failure rejects startup
//   - digest bootstrap failure rejects startup (Python agent must be running)
//   - empty digest rejects startup
//
// Returns the resolved PythonClient with ProjectID + PolicyDigest stamped.
// The Address/Capability from “initial“ are preserved.
func resolvePythonClient(initial platform.PythonClient, projectRoot string, bootstrapDigest digestBootstrapFunc) (platform.PythonClient, error) {
	if strings.TrimSpace(projectRoot) == "" {
		return platform.PythonClient{}, errors.New("gateway: --project-root is required in production (drift detection cannot be disabled)")
	}
	pid, err := computeProjectID(projectRoot)
	if err != nil {
		return platform.PythonClient{}, fmt.Errorf("gateway: compute project_id: %w", err)
	}
	if pid == "" {
		return platform.PythonClient{}, errors.New("gateway: computed project_id is empty")
	}
	initial.ProjectID = pid
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	digest, err := bootstrapDigest(ctx)
	if err != nil {
		return platform.PythonClient{}, fmt.Errorf("gateway: policy_digest bootstrap failed: %w (Python agent must be running before the gateway starts)", err)
	}
	if digest == "" {
		return platform.PythonClient{}, errors.New("gateway: policy_digest bootstrap returned empty digest")
	}
	initial.PolicyDigest = digest
	return initial, nil
}

// computeProjectID mirrors Python's “compute_project_id(project_root)“:
// “sha256(realpath(project_root))[:32]“.  An empty “projectRoot“
// returns an empty string (drift detection disabled).  Symlinks are
// resolved first so a project reached via different symlink paths
// maps to the same id — matching Python's “Path.resolve()“.
func computeProjectID(projectRoot string) (string, error) {
	trimmed := strings.TrimSpace(projectRoot)
	if trimmed == "" {
		return "", nil
	}
	resolved, err := filepath.Abs(trimmed)
	if err != nil {
		return "", fmt.Errorf("resolve project root: %w", err)
	}
	if real, err := filepath.EvalSymlinks(resolved); err == nil {
		resolved = real
	}
	// filepath.EvalSymlinks error (e.g. path doesn't exist) is
	// non-fatal — fall back to Abs path.  Python's resolve() also
	// returns the lexical path when the target doesn't exist.
	hash := sha256.Sum256([]byte(resolved))
	return hex.EncodeToString(hash[:])[:32], nil
}
