package auth

import (
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
