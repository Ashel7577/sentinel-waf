package redteam

import (
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// Verdict is how the WAF judged one request, plus how long inspection took.
type Verdict struct {
	Score     int
	Blocked   bool
	Cats      []string
	LatencyNS int64
}

// Target is what the engine drives: the WAF under test and the backend oracle.
type Target struct {
	// Inspect judges a request with the WAF (in-process, exact score + timing).
	Inspect func(Request) Verdict
	// Lands returns the values the demo backend parsed from the request, so the
	// engine can tell whether a payload reached an application parameter.
	Lands func(Request) []string
}

// Trial is one evaluated (attack, placement) attempt.
type Trial struct {
	Class      Class  `json:"class"`
	Base       string `json:"base"`
	Mutator    string `json:"mutator"`
	Payload    string `json:"payload"`
	Placement  string `json:"placement"`
	Structural bool   `json:"structural"`
	Generation int    `json:"generation"`
	Landed     bool   `json:"landed"`
	Blocked    bool   `json:"blocked"`
	Score      int    `json:"score"`
	Bypass     bool   `json:"bypass"` // landed AND not blocked: a real evasion
	LatencyNS  int64  `json:"latency_ns"`
}

// Report is the full outcome of a campaign.
type Report struct {
	TrialCount  int                 `json:"trials"`
	Landed      int                 `json:"landed_attacks"`
	Blocked     int                 `json:"blocked_of_landed"`
	Bypasses    []Trial             `json:"bypasses"`
	ByClass     map[Class]ClassStat `json:"by_class"`
	Generations int                 `json:"generations"`
	Latency     Latency             `json:"inspection_latency_ns"`
	Benign      BenignStat          `json:"benign"`
	Tuning      []TunePoint         `json:"tuning"`
	History     []RunSummary        `json:"history,omitempty"`
	Shots       []Shot              `json:"-"`
	Started     time.Time           `json:"started"`
	DurationMS  int64               `json:"duration_ms"`
	all         []Trial
}

type ClassStat struct {
	Landed   int     `json:"landed"`
	Blocked  int     `json:"blocked"`
	Bypassed int     `json:"bypassed"`
	Rate     float64 `json:"detection_rate"`
}

type Latency struct {
	Samples int   `json:"samples"`
	P50     int64 `json:"p50"`
	P95     int64 `json:"p95"`
	P99     int64 `json:"p99"`
	Max     int64 `json:"max"`
}

type BenignStat struct {
	Total   int     `json:"total"`
	Blocked int     `json:"blocked"`
	FPRate  float64 `json:"fp_rate"`
}

// TunePoint is detection vs false positives at one operating point.
type TunePoint struct {
	Paranoia      int     `json:"paranoia"`
	Threshold     int     `json:"threshold"`
	DetectionRate float64 `json:"detection_rate"`
	FPRate        float64 `json:"fp_rate"`
	Recommended   bool    `json:"recommended"`
}

// Options bound the autonomous search.
type Options struct {
	MaxGenerations int
	MaxTrials      int
	Benign         []string // benign request strings (sent as ?q=)
	Log            func(string)
}

func (o *Options) def() {
	if o.MaxGenerations == 0 {
		o.MaxGenerations = 4
	}
	if o.MaxTrials == 0 {
		o.MaxTrials = 6000
	}
	if o.Log == nil {
		o.Log = func(string) {}
	}
}

// Run drives the autonomous campaign and returns the report. The report's
// trials are also available via Trials() for evidence capture.
func Run(t Target, o Options) *Report {
	o.def()
	r := &Report{ByClass: map[Class]ClassStat{}, Started: time.Now()}
	start := time.Now()
	pls := placements()
	muts := mutators()
	mutByName := map[string]func(string) string{}
	for _, m := range muts {
		mutByName[m.Name] = m.Fn
	}

	// evaluate one base payload across every applicable placement, at a generation.
	eval := func(cls Class, base, mut, payload string, gen int) (landedBlocked bool) {
		for _, pl := range pls {
			if !placementFits(cls, pl) {
				continue
			}
			if len(r.all) >= o.MaxTrials {
				return
			}
			req := pl.Build(payload)
			v := t.Inspect(req)
			mk := markerFor(base, cls, payload)
			if pl.Splits {
				mk = payload // split payloads must arrive whole in one value
			}
			landed := marks(t.Lands(req), mk)
			tr := Trial{Class: cls, Base: base, Mutator: mut, Payload: clip(payload, 160), Placement: pl.Name,
				Structural: pl.Structural, Generation: gen, Landed: landed, Blocked: v.Blocked, Score: v.Score,
				Bypass: landed && !v.Blocked, LatencyNS: v.LatencyNS}
			r.all = append(r.all, tr)
			if landed && v.Blocked {
				landedBlocked = true
			}
		}
		return
	}

	// generation 0: seeds, identity.
	type pop struct {
		cls  Class
		base string
	}
	var frontier []pop
	for _, s := range seeds() {
		if eval(s.Class, s.Payload, "identity", s.Payload, 0) {
			frontier = append(frontier, pop{s.Class, s.Payload})
		}
	}
	o.Log("generation 0: " + itoa(len(r.all)) + " trials, " + itoa(len(frontier)) + " attacks the WAF caught -> searching evasions")

	// generations: mutate the caught attacks, looking for a variant that evades.
	gen := 0
	for gen < o.MaxGenerations && len(frontier) > 0 && len(r.all) < o.MaxTrials {
		gen++
		seenNext := map[string]bool{}
		var next []pop
		for _, f := range frontier {
			for _, m := range muts {
				if m.Name == "identity" {
					continue
				}
				pm := m.Fn(f.base)
				if pm == f.base || seenNext[string(f.cls)+pm] {
					continue
				}
				seenNext[string(f.cls)+pm] = true
				if eval(f.cls, f.base, m.Name, pm, gen) {
					next = append(next, pop{f.cls, pm}) // still caught: keep mutating it
				}
			}
		}
		o.Log("generation " + itoa(gen) + ": " + itoa(len(r.all)) + " trials total, frontier " + itoa(len(next)))
		frontier = next
	}
	r.Generations = gen

	// aggregate
	for _, tr := range r.all {
		cs := r.ByClass[tr.Class]
		if tr.Landed {
			r.Landed++
			cs.Landed++
			if tr.Blocked {
				r.Blocked++
				cs.Blocked++
			} else {
				cs.Bypassed++
				r.Bypasses = append(r.Bypasses, tr)
			}
		}
		r.ByClass[tr.Class] = cs
	}
	for c, cs := range r.ByClass {
		if cs.Landed > 0 {
			cs.Rate = float64(cs.Blocked) / float64(cs.Landed)
		}
		r.ByClass[c] = cs
	}
	r.TrialCount = len(r.all)
	sort.SliceStable(r.Bypasses, func(i, j int) bool {
		if r.Bypasses[i].Class != r.Bypasses[j].Class {
			return r.Bypasses[i].Class < r.Bypasses[j].Class
		}
		return r.Bypasses[i].Placement < r.Bypasses[j].Placement
	})

	// latency distribution over all inspections
	lats := make([]int64, 0, len(r.all))
	for _, tr := range r.all {
		lats = append(lats, tr.LatencyNS)
	}
	r.Latency = latStats(lats)

	// benign false positives
	for _, b := range o.Benign {
		req := Request{"GET", "/search?q=" + urlq(b), nil, nil}
		r.Benign.Total++
		if t.Inspect(req).Blocked {
			r.Benign.Blocked++
		}
	}
	if r.Benign.Total > 0 {
		r.Benign.FPRate = float64(r.Benign.Blocked) / float64(r.Benign.Total)
	}

	r.DurationMS = time.Since(start).Milliseconds()
	return r
}

// Trials returns every evaluated attempt (for evidence replay).
func (r *Report) Trials() []Trial { return r.all }

// DetectionRate over attacks that actually landed on the backend.
func (r *Report) DetectionRate() float64 {
	if r.Landed == 0 {
		return 0
	}
	return float64(r.Blocked) / float64(r.Landed)
}

func latStats(v []int64) Latency {
	if len(v) == 0 {
		return Latency{}
	}
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	q := func(p float64) int64 { return v[min(int(p*float64(len(v))), len(v)-1)] }
	return Latency{Samples: len(v), P50: q(0.50), P95: q(0.95), P99: q(0.99), Max: v[len(v)-1]}
}

func placementFits(c Class, p Placement) bool {
	// every class fits every placement here; hook for future class-specific rules
	_ = c
	_ = p
	return true
}

// markerFor returns the substring the backend echoes if this payload landed.
// For encodings the backend decodes (url, json), the decoded marker is sought;
// otherwise the literal marker.
func markerFor(base string, cls Class, payload string) string {
	for _, s := range seeds() {
		if s.Payload == base && s.Class == cls {
			return s.Marker
		}
	}
	return base
}

func marks(got []string, marker string) bool {
	m := strings.ToLower(marker)
	md := strings.ToLower(urlDecode(marker))
	for _, g := range got {
		lg := strings.ToLower(g)
		if strings.Contains(lg, m) || strings.Contains(lg, md) {
			return true
		}
	}
	return false
}

func jsonMarshalString(s string) (string, error) {
	b, err := json.Marshal(s)
	return string(b), err
}
