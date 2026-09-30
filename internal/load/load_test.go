package load

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arseniyyx/relgate/internal/config"
)

func TestLoadCountsAndErrorRate(t *testing.T) {
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every 5th request is a 500 to exercise the error path.
		if atomic.AddInt64(&n, 1)%5 == 0 {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := &config.Config{Target: srv.URL, Load: config.LoadConfig{
		Path: "/", DurationSec: 1, Concurrency: 4, MaxRPS: 100,
	}}
	res := Run(context.Background(), srv.Client(), cfg)

	if !res.Ran || res.Requests == 0 {
		t.Fatalf("no requests made: %+v", res)
	}
	if res.Errors == 0 {
		t.Error("expected some errors from the 500 responses")
	}
	if res.ErrorRate <= 0 || res.ErrorRate >= 1 {
		t.Errorf("error rate out of range: %f", res.ErrorRate)
	}
	if res.P95 <= 0 {
		t.Error("expected a positive p95")
	}
}

func TestLoadRespectsRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := &config.Config{Target: srv.URL, Load: config.LoadConfig{
		Path: "/", DurationSec: 1, Concurrency: 50, MaxRPS: 20,
	}}
	start := time.Now()
	res := Run(context.Background(), srv.Client(), cfg)
	_ = time.Since(start)

	// With 20 rps over ~1s we expect on the order of 20 requests, not thousands.
	if res.Requests > 60 {
		t.Errorf("rate limit not honored: %d requests in ~1s at 20 rps", res.Requests)
	}
}

func TestPercentile(t *testing.T) {
	s := []time.Duration{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	if got := percentile(s, 0.50); got != 60 {
		t.Errorf("p50 = %v, want 60", got)
	}
	if got := percentile(s, 0.95); got != 100 {
		t.Errorf("p95 = %v, want 100", got)
	}
	if got := percentile(nil, 0.5); got != 0 {
		t.Errorf("percentile(nil) = %v, want 0", got)
	}
}
