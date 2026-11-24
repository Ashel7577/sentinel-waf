package server

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Ashel7577/sentinel-waf/internal/waf"
)

// Inspection latency histogram buckets, microseconds.
var bucketsMicros = []float64{10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}

// Event is a blocked or flagged request shown on the dashboard.
type Event struct {
	Time       time.Time `json:"time"`
	ID         string    `json:"id"`
	IP         string    `json:"ip"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	Score      int       `json:"score"`
	Action     string    `json:"action"`
	Categories []string  `json:"categories"`
	Message    string    `json:"message"`
}

// Metrics collects counters and a latency histogram without external deps.
type Metrics struct {
	start time.Time

	requests, blocked, flagged, rateLimited, tooLarge, upstreamErr atomic.Int64

	hist     [11]atomic.Int64 // len(bucketsMicros)+1
	sumMicro atomic.Int64

	mu     sync.Mutex
	byCat  map[string]int64
	byRule map[int]int64
	recent []Event // ring, newest last
}

func newMetrics() *Metrics {
	return &Metrics{start: time.Now(), byCat: map[string]int64{}, byRule: map[int]int64{}}
}

func (m *Metrics) observe(res waf.Result, d time.Duration) {
	m.requests.Add(1)
	us := float64(d.Nanoseconds()) / 1e3
	m.sumMicro.Add(int64(us))
	i := sort.SearchFloat64s(bucketsMicros, us)
	m.hist[i].Add(1)
	if len(res.Findings) == 0 {
		return
	}
	m.mu.Lock()
	for _, c := range res.Categories() {
		m.byCat[c]++
	}
	for _, f := range res.Findings {
		m.byRule[f.RuleID]++
	}
	m.mu.Unlock()
}

func (m *Metrics) record(e Event) {
	m.mu.Lock()
	m.recent = append(m.recent, e)
	if len(m.recent) > 100 {
		m.recent = m.recent[len(m.recent)-100:]
	}
	m.mu.Unlock()
}

// quantile estimates a latency quantile (µs) from the histogram.
func (m *Metrics) quantile(q float64) float64 {
	var counts [11]int64
	var total int64
	for i := range counts {
		counts[i] = m.hist[i].Load()
		total += counts[i]
	}
	if total == 0 {
		return 0
	}
	target := int64(q * float64(total))
	var cum int64
	for i, c := range counts {
		cum += c
		if cum > target {
			if i < len(bucketsMicros) {
				return bucketsMicros[i]
			}
			return bucketsMicros[len(bucketsMicros)-1]
		}
	}
	return bucketsMicros[len(bucketsMicros)-1]
}

// Stats is the JSON document served to the dashboard.
type Stats struct {
	UptimeSeconds  int64            `json:"uptime_seconds"`
	Requests       int64            `json:"requests"`
	Blocked        int64            `json:"blocked"`
	Flagged        int64            `json:"flagged"`
	RateLimited    int64            `json:"rate_limited"`
	TooLarge       int64            `json:"too_large"`
	UpstreamErrors int64            `json:"upstream_errors"`
	AvgInspectUS   float64          `json:"avg_inspect_us"`
	P50InspectUS   float64          `json:"p50_inspect_us_le"`
	P99InspectUS   float64          `json:"p99_inspect_us_le"`
	Categories     map[string]int64 `json:"categories"`
	TopRules       map[int]int64    `json:"top_rules"`
	Recent         []Event          `json:"recent"`
}

func (m *Metrics) snapshot() Stats {
	s := Stats{
		UptimeSeconds:  int64(time.Since(m.start).Seconds()),
		Requests:       m.requests.Load(),
		Blocked:        m.blocked.Load(),
		Flagged:        m.flagged.Load(),
		RateLimited:    m.rateLimited.Load(),
		TooLarge:       m.tooLarge.Load(),
		UpstreamErrors: m.upstreamErr.Load(),
		P50InspectUS:   m.quantile(0.50),
		P99InspectUS:   m.quantile(0.99),
		Categories:     map[string]int64{},
		TopRules:       map[int]int64{},
	}
	if s.Requests > 0 {
		s.AvgInspectUS = float64(m.sumMicro.Load()) / float64(s.Requests)
	}
	m.mu.Lock()
	for k, v := range m.byCat {
		s.Categories[k] = v
	}
	for k, v := range m.byRule {
		s.TopRules[k] = v
	}
	s.Recent = make([]Event, len(m.recent))
	for i := range m.recent { // newest first
		s.Recent[i] = m.recent[len(m.recent)-1-i]
	}
	m.mu.Unlock()
	return s
}

// writePrometheus emits the Prometheus text exposition format.
func (m *Metrics) writePrometheus(w io.Writer) {
	s := m.snapshot()
	counter := func(name, help string, v int64) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
	}
	counter("waf_requests_total", "Requests inspected.", s.Requests)
	counter("waf_blocked_total", "Requests blocked by detection.", s.Blocked)
	counter("waf_flagged_total", "Requests with findings below threshold or in monitor mode.", s.Flagged)
	counter("waf_rate_limited_total", "Requests rejected by rate limiting.", s.RateLimited)
	counter("waf_body_too_large_total", "Requests rejected for body size.", s.TooLarge)
	counter("waf_upstream_errors_total", "Upstream connection failures.", s.UpstreamErrors)

	fmt.Fprintf(w, "# HELP waf_findings_total Requests with findings per category.\n# TYPE waf_findings_total counter\n")
	cats := make([]string, 0, len(s.Categories))
	for c := range s.Categories {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	for _, c := range cats {
		fmt.Fprintf(w, "waf_findings_total{category=%q} %d\n", c, s.Categories[c])
	}

	fmt.Fprintf(w, "# HELP waf_inspect_duration_seconds Time spent inspecting a request.\n# TYPE waf_inspect_duration_seconds histogram\n")
	var cum int64
	for i, b := range bucketsMicros {
		cum += m.hist[i].Load()
		fmt.Fprintf(w, "waf_inspect_duration_seconds_bucket{le=\"%g\"} %d\n", b/1e6, cum)
	}
	cum += m.hist[len(bucketsMicros)].Load()
	fmt.Fprintf(w, "waf_inspect_duration_seconds_bucket{le=\"+Inf\"} %d\n", cum)
	fmt.Fprintf(w, "waf_inspect_duration_seconds_sum %g\n", float64(m.sumMicro.Load())/1e6)
	fmt.Fprintf(w, "waf_inspect_duration_seconds_count %d\n", cum)
}
