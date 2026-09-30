// Package security runs passive security checks against a target. "Passive" means
// it reads what the server returns and inspects headers and error responses; it
// sends no exploit payloads and mutates no state. Everything here is the kind of
// check a developer would run against their own service before a release.
package security

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

	"github.com/arseniyyx/relgate/internal/config"
	"github.com/arseniyyx/relgate/internal/report"
)

// Client is the subset of http.Client the checks need, so tests can inject a fake.
type Client interface {
	Do(req *http.Request) (*http.Response, error)
}

// Run performs every enabled security check and returns the findings.
func Run(ctx context.Context, client Client, cfg *config.Config) report.SecurityResult {
	res := report.SecurityResult{Ran: true}
	for _, path := range cfg.Security.Paths {
		res.Findings = append(res.Findings, checkPath(ctx, client, cfg, path)...)
	}
	return res
}

func checkPath(ctx context.Context, client Client, cfg *config.Config, path string) []report.Finding {
	url := strings.TrimRight(cfg.Target, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return []report.Finding{{
			Severity: report.Info, Title: "request could not be built",
			Detail: err.Error(), Path: path,
		}}
	}
	resp, err := client.Do(req)
	if err != nil {
		return []report.Finding{{
			Severity: report.Info, Title: "target unreachable",
			Detail: err.Error(), Path: path,
		}}
	}
	defer resp.Body.Close()

	var findings []report.Finding
	findings = append(findings, checkHeaders(resp, path, strings.HasPrefix(url, "https://"))...)
	findings = append(findings, checkCookies(resp, path)...)
	findings = append(findings, checkCORS(resp, path)...)
	findings = append(findings, checkTLS(resp, path)...)
	findings = append(findings, checkServerLeak(resp, path)...)
	return findings
}

// headerCheck describes one "this security header should be present" rule.
type headerCheck struct {
	name     string
	severity report.Severity
	title    string
	detail   string
}

var securityHeaders = []headerCheck{
	{"Content-Security-Policy", report.Medium, "missing Content-Security-Policy",
		"a CSP limits where scripts and other resources may load from, mitigating XSS"},
	{"X-Content-Type-Options", report.Low, "missing X-Content-Type-Options",
		"set it to 'nosniff' so browsers do not guess content types"},
	{"X-Frame-Options", report.Low, "missing X-Frame-Options",
		"set DENY or SAMEORIGIN (or a frame-ancestors CSP) to prevent clickjacking"},
	{"Referrer-Policy", report.Low, "missing Referrer-Policy",
		"controls how much referrer information is sent to other origins"},
}

func checkHeaders(resp *http.Response, path string, isHTTPS bool) []report.Finding {
	var findings []report.Finding
	for _, h := range securityHeaders {
		if resp.Header.Get(h.name) == "" {
			findings = append(findings, report.Finding{
				Severity: h.severity, Title: h.title, Detail: h.detail, Path: path,
			})
		}
	}
	if isHTTPS && resp.Header.Get("Strict-Transport-Security") == "" {
		findings = append(findings, report.Finding{
			Severity: report.Medium, Title: "missing Strict-Transport-Security",
			Detail: "HSTS tells browsers to only use HTTPS for this host", Path: path,
		})
	}
	return findings
}

func checkCookies(resp *http.Response, path string) []report.Finding {
	var findings []report.Finding
	for _, ck := range resp.Cookies() {
		if !ck.Secure {
			findings = append(findings, report.Finding{
				Severity: report.Medium, Title: fmt.Sprintf("cookie %q missing Secure", ck.Name),
				Detail: "a Secure cookie is only sent over HTTPS", Path: path,
			})
		}
		if !ck.HttpOnly {
			findings = append(findings, report.Finding{
				Severity: report.Medium, Title: fmt.Sprintf("cookie %q missing HttpOnly", ck.Name),
				Detail: "HttpOnly keeps the cookie out of reach of JavaScript", Path: path,
			})
		}
	}
	return findings
}

func checkCORS(resp *http.Response, path string) []report.Finding {
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := strings.EqualFold(resp.Header.Get("Access-Control-Allow-Credentials"), "true")
	if acao == "*" && acac {
		return []report.Finding{{
			Severity: report.High, Title: "CORS allows any origin with credentials",
			Detail: "Access-Control-Allow-Origin '*' together with credentials exposes " +
				"authenticated responses to any site", Path: path,
		}}
	}
	if acao == "*" {
		return []report.Finding{{
			Severity: report.Low, Title: "CORS allows any origin",
			Detail: "Access-Control-Allow-Origin is '*'; confirm this endpoint is meant to be public",
			Path:   path,
		}}
	}
	return nil
}

func checkTLS(resp *http.Response, path string) []report.Finding {
	if resp.TLS == nil {
		return nil
	}
	if resp.TLS.Version < tls.VersionTLS12 {
		return []report.Finding{{
			Severity: report.High, Title: "obsolete TLS version negotiated",
			Detail: "the server accepted TLS older than 1.2", Path: path,
		}}
	}
	return nil
}

// leakyServerTokens are values in the Server/X-Powered-By headers that reveal an
// exact version, which makes it easy to look up known CVEs for that build.
func checkServerLeak(resp *http.Response, path string) []report.Finding {
	var findings []report.Finding
	for _, name := range []string{"Server", "X-Powered-By"} {
		v := resp.Header.Get(name)
		if v != "" && strings.ContainsAny(v, "0123456789") {
			findings = append(findings, report.Finding{
				Severity: report.Low,
				Title:    fmt.Sprintf("%s header leaks a version: %q", name, v),
				Detail:   "hiding exact versions makes targeted attacks a little harder",
				Path:     path,
			})
		}
	}
	return findings
}
