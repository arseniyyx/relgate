// Package config loads and validates a relgate run configuration.
//
// relgate only ever touches hosts the operator has explicitly listed as their own.
// The allowlist is the safeguard that keeps this a tool for testing your own stack
// rather than a scanner or load generator pointed at arbitrary third parties.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the top-level relgate configuration, loaded from a YAML file.
type Config struct {
	// Target is the base URL to test, e.g. "http://localhost:8000".
	Target string `yaml:"target"`

	// AllowedHosts lists every host relgate is permitted to contact. The target's
	// host must appear here, and so must every requested path's host. This is what
	// stops relgate from being aimed at a host the operator does not control.
	AllowedHosts []string `yaml:"allowed_hosts"`

	// IAmAuthorized must be true. It is a deliberate speed bump: the operator
	// affirms, in their own committed config, that they own or are authorized to
	// test these hosts. Without it relgate refuses to run.
	IAmAuthorized bool `yaml:"i_am_authorized"`

	Security SecurityConfig `yaml:"security"`
	Load     LoadConfig     `yaml:"load"`
}

// SecurityConfig controls the passive security checks.
type SecurityConfig struct {
	Enabled bool `yaml:"enabled"`
	// Paths to probe for headers/misconfigurations. Defaults to ["/"].
	Paths []string `yaml:"paths"`
	// FailOn is the lowest severity that fails the run: "high", "medium", or "low".
	FailOn string `yaml:"fail_on"`
}

// LoadConfig controls the load test. relgate caps concurrency and rate so a
// misconfigured run cannot accidentally behave like a flood.
type LoadConfig struct {
	Enabled     bool          `yaml:"enabled"`
	Path        string        `yaml:"path"`
	DurationSec int           `yaml:"duration_seconds"`
	Concurrency int           `yaml:"concurrency"`
	MaxRPS      int           `yaml:"max_rps"`
	Thresholds  LoadThreshold `yaml:"thresholds"`
}

// LoadThreshold is the pass/fail bar for a load run.
type LoadThreshold struct {
	P95Ms        int     `yaml:"p95_ms"`
	MaxErrorRate float64 `yaml:"max_error_rate"`
}

// Hard safety ceilings. A config may ask for less, never more.
const (
	MaxConcurrency  = 200
	MaxRPSCeiling   = 2000
	MaxDurationSec  = 300
	MaxTargetsProbe = 50
)

// Load reads, parses, validates and normalizes a config file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	c.applyDefaults()
	return &c, nil
}

func (c *Config) validate() error {
	if !c.IAmAuthorized {
		return fmt.Errorf(
			"refusing to run: set i_am_authorized: true in the config to affirm you own " +
				"or are authorized to test these hosts")
	}
	if c.Target == "" {
		return fmt.Errorf("target is required")
	}
	u, err := url.Parse(c.Target)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("target must be an http(s) URL, got %q", c.Target)
	}
	if len(c.AllowedHosts) == 0 {
		return fmt.Errorf("allowed_hosts must list at least one host")
	}
	if !c.HostAllowed(u.Host) {
		return fmt.Errorf("target host %q is not in allowed_hosts", u.Host)
	}
	if c.Load.Concurrency > MaxConcurrency {
		return fmt.Errorf("load.concurrency %d exceeds the safety ceiling of %d",
			c.Load.Concurrency, MaxConcurrency)
	}
	if c.Load.MaxRPS > MaxRPSCeiling {
		return fmt.Errorf("load.max_rps %d exceeds the safety ceiling of %d",
			c.Load.MaxRPS, MaxRPSCeiling)
	}
	if c.Load.DurationSec > MaxDurationSec {
		return fmt.Errorf("load.duration_seconds %d exceeds the safety ceiling of %d",
			c.Load.DurationSec, MaxDurationSec)
	}
	return nil
}

// HostAllowed reports whether host (with or without a port) is on the allowlist.
func (c *Config) HostAllowed(host string) bool {
	h := hostOnly(host)
	for _, a := range c.AllowedHosts {
		if strings.EqualFold(hostOnly(a), h) {
			return true
		}
	}
	return false
}

func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func (c *Config) applyDefaults() {
	if len(c.Security.Paths) == 0 {
		c.Security.Paths = []string{"/"}
	}
	if len(c.Security.Paths) > MaxTargetsProbe {
		c.Security.Paths = c.Security.Paths[:MaxTargetsProbe]
	}
	if c.Security.FailOn == "" {
		c.Security.FailOn = "high"
	}
	if c.Load.Path == "" {
		c.Load.Path = "/"
	}
	if c.Load.DurationSec == 0 {
		c.Load.DurationSec = 10
	}
	if c.Load.Concurrency == 0 {
		c.Load.Concurrency = 10
	}
	if c.Load.MaxRPS == 0 {
		c.Load.MaxRPS = 200
	}
	if c.Load.Thresholds.P95Ms == 0 {
		c.Load.Thresholds.P95Ms = 500
	}
	if c.Load.Thresholds.MaxErrorRate == 0 {
		c.Load.Thresholds.MaxErrorRate = 0.01
	}
}
