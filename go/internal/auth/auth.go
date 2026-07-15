package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
)

type principalContextKey struct{}

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
		provided := r.Header.Get("X-Khaos-Key")
		providedDigest := sha256.Sum256([]byte(provided))
		expectedDigest := sha256.Sum256([]byte(apiKey))
		if subtle.ConstantTimeCompare(providedDigest[:], expectedDigest[:]) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		principal := "api-key:" + hex.EncodeToString(expectedDigest[:])
		next.ServeHTTP(w, r.WithContext(context.WithValue(
			r.Context(), principalContextKey{}, principal,
		)))
	})
}
