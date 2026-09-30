// Package load runs a bounded load test against a single endpoint the operator owns.
//
// It is deliberately not a stress weapon: concurrency, request rate and duration are
// all capped by config validation, and the default rate is modest. The goal is to
// catch a latency or error-rate regression before it reaches production, the same job
// a tool like k6 or Locust does in CI.
package load

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/arseniyyx/relgate/internal/config"
	"github.com/arseniyyx/relgate/internal/report"
)

// Client is the subset of http.Client the runner needs.
type Client interface {
	Do(req *http.Request) (*http.Response, error)
}

// Run drives the load test and returns aggregated results.
func Run(ctx context.Context, client Client, cfg *config.Config) report.LoadResult {
	url := strings.TrimRight(cfg.Target, "/") + cfg.Load.Path
	limiter := newTicker(cfg.Load.MaxRPS)
	defer limiter.close()

	deadline := time.Now().Add(time.Duration(cfg.Load.DurationSec) * time.Second)
	runCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	var (
		mu       sync.Mutex
		samples  []time.Duration
		errors   int
		requests int
	)

	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < cfg.Load.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if err := limiter.wait(runCtx); err != nil {
					return // deadline reached
				}
				d, ok := doRequest(runCtx, client, url)
				if runCtx.Err() != nil {
					return
				}
				mu.Lock()
				requests++
				if ok {
					samples = append(samples, d)
				} else {
					errors++
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	return aggregate(samples, errors, requests, elapsed)
}

func doRequest(ctx context.Context, client Client, url string) (time.Duration, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, false
	}
	t0 := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, false
	}
	d := time.Since(t0)
	// Drain and close so the connection can be reused.
	_ = resp.Body.Close()
	ok := resp.StatusCode < 500
	return d, ok
}

func aggregate(samples []time.Duration, errors, requests int, elapsed time.Duration) report.LoadResult {
	res := report.LoadResult{
		Ran:      true,
		Requests: requests,
		Errors:   errors,
	}
	if requests > 0 {
		res.ErrorRate = float64(errors) / float64(requests)
	}
	if elapsed > 0 {
		res.RPS = float64(requests) / elapsed.Seconds()
	}
	if len(samples) > 0 {
		sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
		res.P50 = percentile(samples, 0.50)
		res.P95 = percentile(samples, 0.95)
		res.P99 = percentile(samples, 0.99)
		res.Max = samples[len(samples)-1]
	}
	return res
}

// percentile returns the p-th percentile (0..1) using nearest-rank.
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(p * float64(len(sorted)))
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
