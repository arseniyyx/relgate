package report

import (
	"strings"
	"testing"
	"time"
)

func TestFinalizePassesClean(t *testing.T) {
	r := &Report{
		Security: SecurityResult{Ran: true},
		Load:     LoadResult{Ran: true, P95: 100 * time.Millisecond, ErrorRate: 0},
	}
	r.Finalize(High, 500, 0.01)
	if !r.Passed {
		t.Fatalf("expected pass, reasons: %v", r.Reasons)
	}
}

func TestFinalizeFailsOnHighFinding(t *testing.T) {
	r := &Report{Security: SecurityResult{Ran: true, Findings: []Finding{
		{Severity: High, Title: "bad"},
		{Severity: Low, Title: "minor"},
	}}}
	r.Finalize(High, 500, 0.01)
	if r.Passed {
		t.Fatal("expected fail on a high finding")
	}
}

func TestFinalizeIgnoresLowWhenFailOnHigh(t *testing.T) {
	r := &Report{Security: SecurityResult{Ran: true, Findings: []Finding{{Severity: Low, Title: "minor"}}}}
	r.Finalize(High, 500, 0.01)
	if !r.Passed {
		t.Fatal("low finding should not fail when fail_on is high")
	}
}

func TestFinalizeFailsOnLatency(t *testing.T) {
	r := &Report{Load: LoadResult{Ran: true, P95: 900 * time.Millisecond}}
	r.Finalize(High, 500, 0.5)
	if r.Passed {
		t.Fatal("expected fail on p95 over threshold")
	}
}

func TestFinalizeFailsOnErrorRate(t *testing.T) {
	r := &Report{Load: LoadResult{Ran: true, P95: 10 * time.Millisecond, ErrorRate: 0.2}}
	r.Finalize(High, 500, 0.01)
	if r.Passed {
		t.Fatal("expected fail on error rate over threshold")
	}
}

func TestMarkdownContainsVerdict(t *testing.T) {
	r := &Report{Target: "http://localhost", Load: LoadResult{Ran: true}}
	r.Finalize(High, 500, 0.01)
	md := r.Markdown()
	if !strings.Contains(md, "PASS") || !strings.Contains(md, "http://localhost") {
		t.Errorf("markdown missing verdict or target:\n%s", md)
	}
}
