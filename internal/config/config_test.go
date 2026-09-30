package config

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "relgate.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValid(t *testing.T) {
	c, err := Load(write(t, `
target: http://localhost:8000
allowed_hosts: [localhost]
i_am_authorized: true
security:
  enabled: true
load:
  enabled: true
`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Security.FailOn != "high" {
		t.Errorf("FailOn default = %q, want high", c.Security.FailOn)
	}
	if c.Load.Concurrency != 10 || c.Load.MaxRPS != 200 {
		t.Errorf("load defaults not applied: %+v", c.Load)
	}
	if len(c.Security.Paths) != 1 || c.Security.Paths[0] != "/" {
		t.Errorf("security paths default = %v", c.Security.Paths)
	}
}

func TestRefusesWithoutAuthorization(t *testing.T) {
	_, err := Load(write(t, `
target: http://localhost:8000
allowed_hosts: [localhost]
`))
	if err == nil {
		t.Fatal("expected refusal without i_am_authorized")
	}
}

func TestRefusesTargetNotInAllowlist(t *testing.T) {
	_, err := Load(write(t, `
target: http://evil.example.com
allowed_hosts: [localhost]
i_am_authorized: true
`))
	if err == nil {
		t.Fatal("expected refusal when target host is not allowlisted")
	}
}

func TestRefusesOverCeiling(t *testing.T) {
	_, err := Load(write(t, `
target: http://localhost:8000
allowed_hosts: [localhost]
i_am_authorized: true
load:
  concurrency: 100000
`))
	if err == nil {
		t.Fatal("expected refusal when concurrency exceeds the ceiling")
	}
}

func TestHostAllowedIgnoresPortAndCase(t *testing.T) {
	c := &Config{AllowedHosts: []string{"Localhost", "api.example.com"}}
	for _, h := range []string{"localhost", "localhost:8000", "API.EXAMPLE.COM:443"} {
		if !c.HostAllowed(h) {
			t.Errorf("HostAllowed(%q) = false, want true", h)
		}
	}
	if c.HostAllowed("other.com") {
		t.Error("HostAllowed(other.com) = true, want false")
	}
}
