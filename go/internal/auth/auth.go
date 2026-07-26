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
	"net/http"
	"strconv"
	"strings"
	"time"
)

type principalContextKey struct{}

const browserSessionCookie = "khaos_browser_session"
const browserSessionTTL = 15 * time.Minute

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
	if apiKey == "" {
		return fmt.Errorf("gateway authentication unavailable")
	}
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate browser session nonce: %w", err)
	}
	expires := time.Now().Add(browserSessionTTL)
	payload := strconv.FormatInt(expires.Unix(), 10) + "." + base64.RawURLEncoding.EncodeToString(nonce)
	signature := signBrowserSession(payload, apiKey)
	http.SetCookie(w, &http.Cookie{
		Name:     browserSessionCookie,
		Value:    payload + "." + signature,
		Path:     "/",
		MaxAge:   int(browserSessionTTL.Seconds()),
		Expires:  expires,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})
	return nil
}

func validBrowserSession(r *http.Request, apiKey string, now time.Time) bool {
	cookie, err := r.Cookie(browserSessionCookie)
	if err != nil {
		return false
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 3 {
		return false
	}
	expires, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || expires <= now.Unix() || expires > now.Add(browserSessionTTL).Unix()+1 {
		return false
	}
	payload := parts[0] + "." + parts[1]
	expected, err := base64.RawURLEncoding.DecodeString(signBrowserSession(payload, apiKey))
	if err != nil {
		return false
	}
	provided, err := base64.RawURLEncoding.DecodeString(parts[2])
	return err == nil && hmac.Equal(provided, expected)
}

func signBrowserSession(payload, apiKey string) string {
	key := sha256.Sum256([]byte("khaos-browser-session-v1\x00" + apiKey))
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
