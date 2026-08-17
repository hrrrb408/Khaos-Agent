package auth

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testMasterKey = "0123456789abcdef0123456789abcdef"

func TestBrowserSessionAuthenticatesWithoutExposingMasterKey(t *testing.T) {
	bootstrap := httptest.NewRequest(http.MethodPost, "/api/auth/session", nil)
	recorder := httptest.NewRecorder()
	if err := SetBrowserSession(recorder, bootstrap, testMasterKey); err != nil {
		t.Fatal(err)
	}
	result := recorder.Result()
	cookies := result.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies=%d", len(cookies))
	}
	cookie := cookies[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("unsafe cookie attributes: %#v", cookie)
	}
	if strings.Contains(cookie.Value, testMasterKey) {
		t.Fatal("browser session exposed master key")
	}

	called := false
	handler := Middleware(testMasterKey, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	request := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	request.AddCookie(cookie)
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if !called {
		t.Fatal("valid browser session was rejected")
	}
}

func TestBrowserSessionRejectsTampering(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	if err := SetBrowserSession(recorder, request, testMasterKey); err != nil {
		t.Fatal(err)
	}
	cookie := recorder.Result().Cookies()[0]
	cookie.Value += "x"

	called := false
	handler := Middleware(testMasterKey, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	probe := httptest.NewRequest(http.MethodGet, "/", nil)
	probe.AddCookie(cookie)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, probe)
	if called || response.Code != http.StatusUnauthorized {
		t.Fatalf("called=%v status=%d", called, response.Code)
	}
}

func TestBrowserSessionSecurePolicyIsExplicit(t *testing.T) {
	_, trustedProxy, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		mode       CookieSecureMode
		remoteAddr string
		forwarded  string
		tls        bool
		wantSecure bool
	}{
		{name: "always on direct http", mode: CookieSecureAlways, remoteAddr: "127.0.0.1:1234", wantSecure: true},
		{name: "never on tls", mode: CookieSecureNever, remoteAddr: "127.0.0.1:1234", tls: true, wantSecure: false},
		{name: "auto trusted forwarded https", mode: CookieSecureAuto, remoteAddr: "10.1.2.3:443", forwarded: "https", wantSecure: true},
		{name: "auto untrusted forwarded https", mode: CookieSecureAuto, remoteAddr: "192.0.2.10:443", forwarded: "https", wantSecure: false},
		{name: "auto direct tls", mode: CookieSecureAuto, remoteAddr: "127.0.0.1:1234", tls: true, wantSecure: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/", nil)
			request.RemoteAddr = test.remoteAddr
			if test.forwarded != "" {
				request.Header.Set("X-Forwarded-Proto", test.forwarded)
			}
			if test.tls {
				request.TLS = &tls.ConnectionState{}
			}
			config := BrowserSessionConfig{
				SecureMode:        test.mode,
				TrustedProxyCIDRs: []*net.IPNet{trustedProxy},
			}
			if err := SetBrowserSessionWithConfig(recorder, request, testMasterKey, config); err != nil {
				t.Fatal(err)
			}
			cookie := recorder.Result().Cookies()[0]
			if cookie.Secure != test.wantSecure {
				t.Fatalf("Secure=%v want %v", cookie.Secure, test.wantSecure)
			}
		})
	}
}

// TestRevokeAllSessionsInvalidatesOutstandingCookies (Batch 11.8):
// RevokeAllSessions bumps the server-side epoch so a previously-issued
// cookie is rejected on its next request.
func TestRevokeAllSessionsInvalidatesOutstandingCookies(t *testing.T) {
	// Issue a session cookie.
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	if err := SetBrowserSession(recorder, request, testMasterKey); err != nil {
		t.Fatal(err)
	}
	cookie := recorder.Result().Cookies()[0]

	// The cookie is valid before revocation.
	called := false
	handler := Middleware(testMasterKey, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	probe := httptest.NewRequest(http.MethodGet, "/", nil)
	probe.AddCookie(cookie)
	handler.ServeHTTP(httptest.NewRecorder(), probe)
	if !called {
		t.Fatal("cookie should be valid before revocation")
	}

	// Revoke all sessions.
	RevokeAllSessions()

	// The same cookie is now rejected.
	called = false
	probe2 := httptest.NewRequest(http.MethodGet, "/", nil)
	probe2.AddCookie(cookie)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, probe2)
	if called || response.Code != http.StatusUnauthorized {
		t.Fatalf("after revocation: called=%v status=%d", called, response.Code)
	}
}
