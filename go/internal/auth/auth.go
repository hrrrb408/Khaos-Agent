package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type principalContextKey struct{}

const browserSessionCookie = "khaos_browser_session"
const browserSessionTTL = 15 * time.Minute

// CookieSecureMode controls whether browser session cookies carry Secure.
// Production deployments should use CookieSecureAlways; Auto is only for
// explicitly trusted reverse-proxy setups and Never is for local HTTP-only
// development.
type CookieSecureMode string

const (
	CookieSecureAlways CookieSecureMode = "always"
	CookieSecureAuto   CookieSecureMode = "auto"
	CookieSecureNever  CookieSecureMode = "never"
)

// BrowserSessionConfig is the explicit cookie transport policy. Forwarded
// HTTPS headers are considered only when the direct peer is in
// TrustedProxyCIDRs; an arbitrary client cannot turn Secure on or off by
// spoofing X-Forwarded-Proto.
type BrowserSessionConfig struct {
	SecureMode        CookieSecureMode
	TrustedProxyCIDRs []*net.IPNet
}

// DefaultBrowserSessionConfig preserves the local direct-HTTP behavior of the
// legacy helper while making proxy trust explicit.
func DefaultBrowserSessionConfig() BrowserSessionConfig {
	return BrowserSessionConfig{SecureMode: CookieSecureAuto}
}

// Validate checks the configured browser cookie policy before the server
// starts accepting traffic.
func (c BrowserSessionConfig) Validate() error {
	mode := c.SecureMode
	if mode == "" {
		mode = CookieSecureAuto
	}
	switch mode {
	case CookieSecureAlways, CookieSecureAuto, CookieSecureNever:
	default:
		return fmt.Errorf("unsupported browser cookie secure mode %q", c.SecureMode)
	}
	for _, network := range c.TrustedProxyCIDRs {
		if network == nil || network.IP == nil {
			return fmt.Errorf("trusted proxy CIDR is invalid")
		}
	}
	return nil
}

// Batch 11.8 (round-11 §十五.2): session revocation via a server-side
// epoch counter.  Each issued cookie embeds the current epoch; validating
// rejects any cookie whose epoch is older than the current value.
// RevokeAllSessions atomically bumps the epoch, invalidating every
// outstanding cookie without storing per-session state.
var sessionEpoch atomic.Uint64

// Batch 12.4 (round-12 §十一): per-boot nonce generated at package init.
// This ensures that a gateway restart invalidates ALL outstanding cookies
// even when the API key has not been rotated — the boot nonce changes on
// every restart, so the HMAC signature no longer matches.
var bootNonce = func() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Should never happen; fall back to a time-based value.
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}()

// RevokeAllSessions invalidates every outstanding browser session cookie
// by bumping the server-side epoch.  Outstanding cookies (carrying the
// previous epoch) are rejected on their next request.
func RevokeAllSessions() {
	sessionEpoch.Add(1)
}

// PrincipalFromContext returns the authenticated API-key principal.
func PrincipalFromContext(ctx context.Context) (string, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(string)
	return principal, ok && principal != ""
}

// Middleware validates X-Khaos-Key and fails closed when authentication is
// not configured. Public endpoints must be routed outside this middleware.
func Middleware(apiKey string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if apiKey == "" {
			http.Error(w, "gateway authentication unavailable", http.StatusServiceUnavailable)
			return
		}
		expectedDigest := sha256.Sum256([]byte(apiKey))
		provided := r.Header.Get("X-Khaos-Key")
		providedDigest := sha256.Sum256([]byte(provided))
		keyValid := provided != "" && subtle.ConstantTimeCompare(providedDigest[:], expectedDigest[:]) == 1
		cookieValid := validBrowserSession(r, apiKey, time.Now())
		if !keyValid && !cookieValid {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		principal := "api-key:" + hex.EncodeToString(expectedDigest[:])
		next.ServeHTTP(w, r.WithContext(context.WithValue(
			r.Context(), principalContextKey{}, principal,
		)))
	})
}

// SetBrowserSession issues a short-lived, signed, HttpOnly browser session.
// The route calling this function is itself protected by Middleware, so the
// master key is used only for bootstrap and is never returned to JavaScript.
func SetBrowserSession(w http.ResponseWriter, r *http.Request, apiKey string) error {
	return SetBrowserSessionWithConfig(w, r, apiKey, DefaultBrowserSessionConfig())
}

// SetBrowserSessionWithConfig issues a browser session using an explicit
// transport policy. It is separate from SetBrowserSession so existing local
// callers remain source-compatible while production startup can require
// Secure cookies unconditionally.
func SetBrowserSessionWithConfig(w http.ResponseWriter, r *http.Request, apiKey string, config BrowserSessionConfig) error {
	if apiKey == "" {
		return fmt.Errorf("gateway authentication unavailable")
	}
	if err := config.Validate(); err != nil {
		return err
	}
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate browser session nonce: %w", err)
	}
	expires := time.Now().Add(browserSessionTTL)
	// Batch 11.8: embed the current epoch so RevokeAllSessions can
	// invalidate outstanding cookies by bumping it.
	// Batch 12.4: embed the boot nonce so a gateway restart invalidates
	// all outstanding cookies even without API key rotation.
	epoch := sessionEpoch.Load()
	payload := strconv.FormatInt(expires.Unix(), 10) + "." + strconv.FormatUint(epoch, 10) + "." + bootNonce + "." + base64.RawURLEncoding.EncodeToString(nonce)
	signature := signBrowserSession(payload, apiKey)
	http.SetCookie(w, &http.Cookie{
		Name:     browserSessionCookie,
		Value:    payload + "." + signature,
		Path:     "/",
		MaxAge:   int(browserSessionTTL.Seconds()),
		Expires:  expires,
		HttpOnly: true,
		Secure:   config.secureForRequest(r),
		SameSite: http.SameSiteStrictMode,
	})
	return nil
}

func (c BrowserSessionConfig) secureForRequest(r *http.Request) bool {
	mode := c.SecureMode
	if mode == "" {
		mode = CookieSecureAuto
	}
	switch mode {
	case CookieSecureAlways:
		return true
	case CookieSecureNever:
		return false
	case CookieSecureAuto:
		return r.TLS != nil || c.trustedForwardedHTTPS(r)
	default:
		return true
	}
}

func (c BrowserSessionConfig) trustedForwardedHTTPS(r *http.Request) bool {
	remote := remoteIP(r.RemoteAddr)
	if remote == nil {
		return false
	}
	trusted := false
	for _, network := range c.TrustedProxyCIDRs {
		if network != nil && network.Contains(remote) {
			trusted = true
			break
		}
	}
	if !trusted {
		return false
	}
	if proto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); strings.EqualFold(proto, "https") {
		return true
	}
	for _, element := range strings.Split(r.Header.Get("Forwarded"), ",") {
		for _, parameter := range strings.Split(element, ";") {
			key, value, ok := strings.Cut(strings.TrimSpace(parameter), "=")
			if !ok || !strings.EqualFold(key, "proto") {
				continue
			}
			value = strings.Trim(strings.TrimSpace(value), "\"")
			return strings.EqualFold(value, "https")
		}
	}
	return false
}

func remoteIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		host = strings.Trim(strings.TrimSpace(remoteAddr), "[]")
	}
	return net.ParseIP(host)
}

func validBrowserSession(r *http.Request, apiKey string, now time.Time) bool {
	cookie, err := r.Cookie(browserSessionCookie)
	if err != nil {
		return false
	}
	parts := strings.Split(cookie.Value, ".")
	// Batch 12.4: payload is now expires.epoch.bootNonce.nonce (5 parts
	// total including the signature).
	if len(parts) != 5 {
		// Reject legacy formats (pre-boot-nonce cookies).  A rolling
		// deploy effectively revokes all legacy sessions.
		return false
	}
	expires, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || expires <= now.Unix() || expires > now.Add(browserSessionTTL).Unix()+1 {
		return false
	}
	cookieEpoch, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return false
	}
	// Batch 11.8: reject cookies from a previous epoch (revoked).
	if cookieEpoch != sessionEpoch.Load() {
		return false
	}
	// Batch 12.4: reject cookies from a previous boot (gateway restarted).
	if parts[2] != bootNonce {
		return false
	}
	payload := parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[3]
	expected, err := base64.RawURLEncoding.DecodeString(signBrowserSession(payload, apiKey))
	if err != nil {
		return false
	}
	provided, err := base64.RawURLEncoding.DecodeString(parts[4])
	return err == nil && hmac.Equal(provided, expected)
}

func signBrowserSession(payload, apiKey string) string {
	key := sha256.Sum256([]byte("khaos-browser-session-v1\x00" + apiKey))
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
