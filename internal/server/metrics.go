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

const (
	seriesLen   = 300 // seconds of per-second history
	streamLen   = 400 // all recent requests (for the live flow view)
	threatsLen  = 150 // recent requests with findings
	maxIPsTrack = 2000
)

// EventFinding is one finding attached to a dashboard event.
type EventFinding struct {
	Rule     int    `json:"rule"`
	Category string `json:"cat"`
	Location string `json:"loc"`
	Name     string `json:"name,omitempty"`
	Message  string `json:"msg"`
	Score    int    `json:"score"`
}

// Event is one request as shown on the dashboard.
type Event struct {
	Seq        uint64         `json:"seq"`
	Time       time.Time      `json:"time"`
	ID         string         `json:"id"`
	IP         string         `json:"ip"`
	Method     string         `json:"method"`
	Path       string         `json:"path"`
	Score      int            `json:"score"`
	Action     string         `json:"action"` // allowed | flagged | blocked | rate-limited | too-large
	Categories []string       `json:"categories,omitempty"`
	Message    string         `json:"message,omitempty"`
	InspectUS  int64          `json:"us"`
	Findings   []EventFinding `json:"findings,omitempty"`
}

type secondBucket struct {
	sec                       int64
	allowed, blocked, flagged int64
}

// Metrics collects counters, a latency histogram, a per-second time series
// and recent events, without external dependencies.
type Metrics struct {
	start time.Time

	requests, blocked, flagged, rateLimited, tooLarge, upstreamErr atomic.Int64

	hist     [11]atomic.Int64 // len(bucketsMicros)+1
	sumMicro atomic.Int64

	mu       sync.Mutex
	seq      uint64
	byCat    map[string]int64
	byRule   map[int]int64
	ruleName map[int]string
	byIP     map[string]int64 // requests with findings per client IP
	byLoc    map[string]int64
	series   [seriesLen]secondBucket
	stream   []Event
	threats  []Event
}

func newMetrics() *Metrics {
	return &Metrics{
		start: time.Now(), byCat: map[string]int64{}, byRule: map[int]int64{},
		ruleName: map[int]string{}, byIP: map[string]int64{}, byLoc: map[string]int64{},
	}
}

func (m *Metrics) observe(res waf.Result, d time.Duration) {
	m.requests.Add(1)
	us := float64(d.Nanoseconds()) / 1e3
	m.sumMicro.Add(int64(us))
	m.hist[sort.SearchFloat64s(bucketsMicros, us)].Add(1)
	if len(res.Findings) == 0 {
		return
	}
	m.mu.Lock()
	for _, c := range res.Categories() {
		m.byCat[c]++
	}
	seenRule := map[int]bool{}
	for _, f := range res.Findings {
		if !seenRule[f.RuleID] {
			seenRule[f.RuleID] = true
			m.byRule[f.RuleID]++
			m.ruleName[f.RuleID] = f.Message
		}
		m.byLoc[f.Location]++
	}
	m.mu.Unlock()
}

// record stores an event for the live views and the time series.
func (m *Metrics) record(e Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	e.Seq = m.seq

	sec := e.Time.Unix()
	b := &m.series[sec%seriesLen]
	if b.sec != sec {
		*b = secondBucket{sec: sec}
	}
	switch e.Action {
	case "blocked", "rate-limited", "too-large":
		b.blocked++
	case "flagged":
		b.flagged++
	default:
		b.allowed++
	}

	m.stream = append(m.stream, e)
	if len(m.stream) > streamLen {
		m.stream = m.stream[len(m.stream)-streamLen:]
	}
	if e.Action != "allowed" {
		m.threats = append(m.threats, e)
		if len(m.threats) > threatsLen {
			m.threats = m.threats[len(m.threats)-threatsLen:]
		}
		if _, ok := m.byIP[e.IP]; ok || len(m.byIP) < maxIPsTrack {
			m.byIP[e.IP]++
		}
	}
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
			break
		}
	}
	return bucketsMicros[len(bucketsMicros)-1]
}

// Named counts for sorted lists.
type Named struct {
	Key   string `json:"key"`
	Name  string `json:"name,omitempty"`
	Count int64  `json:"count"`
}

// Point is one second of the time series.
type Point struct {
	T       int64 `json:"t"`
	Allowed int64 `json:"a"`
	Blocked int64 `json:"b"`
	Flagged int64 `json:"f"`
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
	TopRules       []Named          `json:"top_rules"`
	TopIPs         []Named          `json:"top_ips"`
	UniqueIPs      int              `json:"unique_attackers"`
	Locations      []Named          `json:"locations"`
	Histogram      []int64          `json:"histogram"`
	HistBuckets    []float64        `json:"histogram_buckets_us"`
	Series         []Point          `json:"series"`
	Seq            uint64           `json:"seq"`
	Events         []Event          `json:"events"`  // stream events with seq > since (oldest first)
	Threats        []Event          `json:"threats"` // newest first
}

func topN[K comparable](m map[K]int64, n int, key func(K) string, name func(K) string) []Named {
	out := make([]Named, 0, len(m))
	for k, v := range m {
		out = append(out, Named{Key: key(k), Name: name(k), Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func (m *Metrics) snapshot(since uint64, seriesSecs int) Stats {
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
		HistBuckets:    bucketsMicros,
	}
	if s.Requests > 0 {
		s.AvgInspectUS = float64(m.sumMicro.Load()) / float64(s.Requests)
	}
	for i := range m.hist {
		s.Histogram = append(s.Histogram, m.hist[i].Load())
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range m.byCat {
		s.Categories[k] = v
	}
	s.TopRules = topN(m.byRule, 8, func(k int) string { return fmt.Sprint(k) }, func(k int) string { return m.ruleName[k] })
	s.UniqueIPs = len(m.byIP)
	s.TopIPs = topN(m.byIP, 8, func(k string) string { return k }, func(string) string { return "" })
	s.Locations = topN(m.byLoc, 8, func(k string) string { return k }, func(string) string { return "" })

	if seriesSecs <= 0 || seriesSecs > seriesLen {
		seriesSecs = 120
	}
	now := time.Now().Unix()
	for t := now - int64(seriesSecs) + 1; t <= now; t++ {
		b := m.series[t%seriesLen]
		p := Point{T: t}
		if b.sec == t {
			p.Allowed, p.Blocked, p.Flagged = b.allowed, b.blocked, b.flagged
		}
		s.Series = append(s.Series, p)
	}

	s.Seq = m.seq
	for _, e := range m.stream {
		if e.Seq > since {
			s.Events = append(s.Events, e)
		}
	}
	if len(s.Events) > 250 {
		s.Events = s.Events[len(s.Events)-250:]
	}
	n := len(m.threats)
	if n > 60 {
		n = 60
	}
	for i := 0; i < n; i++ {
		s.Threats = append(s.Threats, m.threats[len(m.threats)-1-i])
	}
	return s
}

// writePrometheus emits the Prometheus text exposition format.
func (m *Metrics) writePrometheus(w io.Writer) {
	s := m.snapshot(^uint64(0), 1)
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
		cum += s.Histogram[i]
		fmt.Fprintf(w, "waf_inspect_duration_seconds_bucket{le=\"%g\"} %d\n", b/1e6, cum)
	}
	cum += s.Histogram[len(bucketsMicros)]
	fmt.Fprintf(w, "waf_inspect_duration_seconds_bucket{le=\"+Inf\"} %d\n", cum)
	fmt.Fprintf(w, "waf_inspect_duration_seconds_sum %g\n", float64(m.sumMicro.Load())/1e6)
	fmt.Fprintf(w, "waf_inspect_duration_seconds_count %d\n", cum)
}
