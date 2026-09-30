// Package report holds the result types produced by the checks and renders them
// to the console and to Markdown for a pull-request comment.
package report

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Severity ranks a security finding.
type Severity string

const (
	High   Severity = "high"
	Medium Severity = "medium"
	Low    Severity = "low"
	Info   Severity = "info"
)

func (s Severity) rank() int {
	switch s {
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	default:
		return 0
	}
}

// AtLeast reports whether s is at least as severe as min.
func (s Severity) AtLeast(min Severity) bool { return s.rank() >= min.rank() }

// Finding is one security observation.
type Finding struct {
	Severity Severity
	Title    string
	Detail   string
	Path     string
}

// SecurityResult is the outcome of the security checks.
type SecurityResult struct {
	Ran      bool
	Findings []Finding
}

// LoadResult is the outcome of the load test.
type LoadResult struct {
	Ran           bool
	Requests      int
	Errors        int
	RPS           float64
	P50, P95, P99 time.Duration
	Max           time.Duration
	ErrorRate     float64
}

// Report is the whole run.
type Report struct {
	Target   string
	Security SecurityResult
	Load     LoadResult
	// Passed is the overall gate verdict.
	Passed bool
	// Reasons explains a failure (empty when passed).
	Reasons []string
}

func (r SecurityResult) countAtLeast(min Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity.AtLeast(min) {
			n++
		}
	}
	return n
}

// Console renders a human-readable report for a terminal.
func (r *Report) Console() string {
	var b strings.Builder
	fmt.Fprintf(&b, "relgate report for %s\n", r.Target)
	fmt.Fprintf(&b, "%s\n\n", strings.Repeat("=", 40))

	if r.Security.Ran {
		b.WriteString("Security\n--------\n")
		if len(r.Security.Findings) == 0 {
			b.WriteString("  no findings\n")
		}
		findings := sortedFindings(r.Security.Findings)
		for _, f := range findings {
			fmt.Fprintf(&b, "  [%-6s] %s\n", strings.ToUpper(string(f.Severity)), f.Title)
			if f.Detail != "" {
				fmt.Fprintf(&b, "           %s\n", f.Detail)
			}
		}
		b.WriteString("\n")
	}

	if r.Load.Ran {
		l := r.Load
		b.WriteString("Load\n----\n")
		fmt.Fprintf(&b, "  requests   %d (errors %d, %.2f%%)\n", l.Requests, l.Errors, l.ErrorRate*100)
		fmt.Fprintf(&b, "  throughput %.0f req/s\n", l.RPS)
		fmt.Fprintf(&b, "  latency    p50 %s  p95 %s  p99 %s  max %s\n",
			ms(l.P50), ms(l.P95), ms(l.P99), ms(l.Max))
		b.WriteString("\n")
	}

	if r.Passed {
		b.WriteString("RESULT: PASS\n")
	} else {
		b.WriteString("RESULT: FAIL\n")
		for _, reason := range r.Reasons {
			fmt.Fprintf(&b, "  - %s\n", reason)
		}
	}
	return b.String()
}

// Markdown renders the report as a PR comment.
func (r *Report) Markdown() string {
	var b strings.Builder
	verdict := "✅ **PASS**"
	if !r.Passed {
		verdict = "❌ **FAIL**"
	}
	fmt.Fprintf(&b, "## relgate — %s\n\n", verdict)
	fmt.Fprintf(&b, "Target: `%s`\n\n", r.Target)

	if !r.Passed {
		b.WriteString("**Why it failed**\n")
		for _, reason := range r.Reasons {
			fmt.Fprintf(&b, "- %s\n", reason)
		}
		b.WriteString("\n")
	}

	if r.Load.Ran {
		l := r.Load
		b.WriteString("### Load\n\n")
		b.WriteString("| metric | value |\n|---|---|\n")
		fmt.Fprintf(&b, "| requests | %d |\n", l.Requests)
		fmt.Fprintf(&b, "| error rate | %.2f%% |\n", l.ErrorRate*100)
		fmt.Fprintf(&b, "| throughput | %.0f req/s |\n", l.RPS)
		fmt.Fprintf(&b, "| p50 | %s |\n", ms(l.P50))
		fmt.Fprintf(&b, "| p95 | %s |\n", ms(l.P95))
		fmt.Fprintf(&b, "| p99 | %s |\n", ms(l.P99))
		b.WriteString("\n")
	}

	if r.Security.Ran {
		b.WriteString("### Security\n\n")
		if len(r.Security.Findings) == 0 {
			b.WriteString("No findings.\n\n")
		} else {
			b.WriteString("| severity | finding | path |\n|---|---|---|\n")
			for _, f := range sortedFindings(r.Security.Findings) {
				fmt.Fprintf(&b, "| %s | %s | `%s` |\n",
					string(f.Severity), f.Title, f.Path)
			}
			b.WriteString("\n")
		}
	}
	b.WriteString("<sub>relgate runs only against hosts listed in its config.</sub>\n")
	return b.String()
}

func sortedFindings(in []Finding) []Finding {
	out := make([]Finding, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity.rank() != out[j].Severity.rank() {
			return out[i].Severity.rank() > out[j].Severity.rank()
		}
		return out[i].Title < out[j].Title
	})
	return out
}

func ms(d time.Duration) string {
	return fmt.Sprintf("%dms", d.Milliseconds())
}

// Finalize computes the pass/fail verdict from the results and thresholds.
func (r *Report) Finalize(failOn Severity, p95Ms int, maxErrorRate float64) {
	r.Passed = true
	if r.Security.Ran {
		if n := r.Security.countAtLeast(failOn); n > 0 {
			r.Passed = false
			r.Reasons = append(r.Reasons,
				fmt.Sprintf("%d security finding(s) at or above severity %q", n, failOn))
		}
	}
	if r.Load.Ran {
		if r.Load.P95.Milliseconds() > int64(p95Ms) {
			r.Passed = false
			r.Reasons = append(r.Reasons,
				fmt.Sprintf("p95 latency %s exceeds threshold %dms", ms(r.Load.P95), p95Ms))
		}
		if r.Load.ErrorRate > maxErrorRate {
			r.Passed = false
			r.Reasons = append(r.Reasons,
				fmt.Sprintf("error rate %.2f%% exceeds threshold %.2f%%",
					r.Load.ErrorRate*100, maxErrorRate*100))
		}
	}
}
