// Package run wires the checks together into a single gate run.
package run

import (
	"context"
	"net/http"
	"time"

	"github.com/arseniyyx/relgate/internal/config"
	"github.com/arseniyyx/relgate/internal/load"
	"github.com/arseniyyx/relgate/internal/report"
	"github.com/arseniyyx/relgate/internal/security"
)

// guardedTransport refuses any request whose host is not on the allowlist. It is a
// second line of defense behind config validation: even a redirect to an off-list
// host is blocked, so relgate cannot be steered at a target the operator did not name.
type guardedTransport struct {
	base http.RoundTripper
	cfg  *config.Config
}

func (t *guardedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.cfg.HostAllowed(req.URL.Host) {
		return nil, &blockedHostError{host: req.URL.Host}
	}
	return t.base.RoundTrip(req)
}

type blockedHostError struct{ host string }

func (e *blockedHostError) Error() string {
	return "relgate refused to contact " + e.host + ": not in allowed_hosts"
}

// NewClient builds an HTTP client that enforces the allowlist.
func NewClient(cfg *config.Config) *http.Client {
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &guardedTransport{base: http.DefaultTransport, cfg: cfg},
	}
}

// Execute runs the enabled checks and returns a finalized report.
func Execute(ctx context.Context, client interface {
	security.Client
	load.Client
}, cfg *config.Config) *report.Report {
	rep := &report.Report{Target: cfg.Target}

	if cfg.Security.Enabled {
		rep.Security = security.Run(ctx, client, cfg)
	}
	if cfg.Load.Enabled {
		rep.Load = load.Run(ctx, client, cfg)
	}

	rep.Finalize(
		report.Severity(cfg.Security.FailOn),
		cfg.Load.Thresholds.P95Ms,
		cfg.Load.Thresholds.MaxErrorRate,
	)
	return rep
}
