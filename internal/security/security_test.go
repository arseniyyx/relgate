package security

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/arseniyyx/relgate/internal/config"
	"github.com/arseniyyx/relgate/internal/report"
)

func runAgainst(t *testing.T, h http.HandlerFunc) report.SecurityResult {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	cfg := &config.Config{Target: srv.URL, Security: config.SecurityConfig{Paths: []string{"/"}}}
	return Run(context.Background(), srv.Client(), cfg)
}

func has(res report.SecurityResult, title string) bool {
	for _, f := range res.Findings {
		if f.Title == title {
			return true
		}
	}
	return false
}

func TestFlagsMissingHeaders(t *testing.T) {
	res := runAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	if !has(res, "missing Content-Security-Policy") {
		t.Error("expected a CSP finding")
	}
	if !has(res, "missing X-Frame-Options") {
		t.Error("expected an X-Frame-Options finding")
	}
}

func TestCleanServerHasFewFindings(t *testing.T) {
	res := runAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.WriteHeader(200)
	})
	if has(res, "missing Content-Security-Policy") {
		t.Error("CSP present but still flagged")
	}
}

func TestFlagsInsecureCookie(t *testing.T) {
	res := runAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "x"})
		w.WriteHeader(200)
	})
	if !has(res, `cookie "session" missing Secure`) {
		t.Error("expected an insecure-cookie finding")
	}
	if !has(res, `cookie "session" missing HttpOnly`) {
		t.Error("expected an HttpOnly finding")
	}
}

func TestFlagsWildcardCORSWithCredentials(t *testing.T) {
	res := runAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(200)
	})
	if !has(res, "CORS allows any origin with credentials") {
		t.Error("expected a high-severity CORS finding")
	}
	for _, f := range res.Findings {
		if f.Title == "CORS allows any origin with credentials" && f.Severity != report.High {
			t.Errorf("CORS+credentials should be high, got %s", f.Severity)
		}
	}
}

func TestFlagsServerVersionLeak(t *testing.T) {
	res := runAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.WriteHeader(200)
	})
	if !has(res, `Server header leaks a version: "nginx/1.25.3"`) {
		t.Error("expected a version-leak finding")
	}
}
