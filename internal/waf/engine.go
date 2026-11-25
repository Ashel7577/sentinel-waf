// Package waf ties request parsing, normalization, the analysers and the rule
// file together into an anomaly-scoring inspection engine.
package waf

import (
	"sync/atomic"

	"github.com/Ashel7577/sentinel-waf/internal/detect"
	"github.com/Ashel7577/sentinel-waf/internal/normalize"
)

// Version is the engine version recorded in evidence.
const Version = "0.2.0-dev"

// Config controls blocking decisions.
type Config struct {
	// Threshold is the anomaly score at which a request is blocked. With the
	// default of 5 a single critical finding blocks (CRS-compatible).
	Threshold int
	// Paranoia enables stricter, noisier checks at higher levels (1-4).
	Paranoia int
}

// Finding is one match, tied to where in the request it was found.
type Finding struct {
	RuleID   int    `json:"rule_id"`
	Category string `json:"category"`
	Message  string `json:"message"`
	Score    int    `json:"score"`
	Location string `json:"location"`
	Name     string `json:"name,omitempty"`
	Sample   string `json:"sample,omitempty"`
}

// Result is the verdict for a request.
type Result struct {
	Score    int       `json:"score"`
	Blocked  bool      `json:"blocked"`
	Findings []Finding `json:"findings,omitempty"`
}

// Categories returns the distinct finding categories.
func (r Result) Categories() []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range r.Findings {
		if !seen[f.Category] {
			seen[f.Category] = true
			out = append(out, f.Category)
		}
	}
	return out
}

// Engine is safe for concurrent use. Rules can be swapped at runtime.
type Engine struct {
	cfg   Config
	rules atomic.Pointer[RuleSet]
}

// NewEngine builds an engine. A nil rule set means built-in analysers only.
func NewEngine(cfg Config, rs *RuleSet) *Engine {
	if cfg.Threshold <= 0 {
		cfg.Threshold = detect.Critical
	}
	if cfg.Paranoia <= 0 {
		cfg.Paranoia = 1
	}
	e := &Engine{cfg: cfg}
	if rs != nil {
		e.rules.Store(rs)
	}
	return e
}

// SetRules atomically replaces the rule set (hot reload).
func (e *Engine) SetRules(rs *RuleSet) { e.rules.Store(rs) }

// RuleCount returns the number of loaded rule-file rules.
func (e *Engine) RuleCount() int {
	if rs := e.rules.Load(); rs != nil {
		return len(rs.Rules)
	}
	return 0
}

// Config returns the engine configuration.
func (e *Engine) Config() Config { return e.cfg }

// Which analysers run for each input location.
const (
	aSQLi = 1 << iota
	aXSS
	aCmdI
	aTraversal
	aFile
)

const param = aSQLi | aXSS | aCmdI | aTraversal | aFile

var analysers = map[string]int{
	locSegment:  aSQLi | aXSS | aCmdI,
	locPath:     aTraversal,
	locQuery:    param,
	locBody:     param,
	locJSON:     param,
	locXML:      param,
	locCookie:   param,
	locHeader:   param,
	locFilename: aXSS | aCmdI | aTraversal,
	locKey:      aSQLi | aXSS,
	// header-std, file, body-raw: rule file only
}

// Inspect scores a set of inputs.
func (e *Engine) Inspect(inputs []Input) Result {
	var res Result
	rs := e.rules.Load()
	for _, in := range inputs {
		if in.Location == locParseDiff {
			if in.score > 0 {
				res.Score += in.score
				res.Findings = append(res.Findings, Finding{
					RuleID: parseDiffID(in.Name), Category: "parser-differential", Message: in.Value, Score: in.score,
					Location: in.Location, Name: in.Name,
				})
			}
			continue
		}
		norm := normalize.Value(in.Value)
		if norm == "" {
			continue
		}
		var hits []detect.Hit
		a := analysers[in.Location]
		if a&aSQLi != 0 {
			hits = append(hits, detect.SQLi(norm)...)
		}
		if a&aXSS != 0 {
			hits = append(hits, detect.XSS(norm)...)
		}
		if a&aCmdI != 0 {
			hits = append(hits, detect.CmdI(norm)...)
		}
		if a&aTraversal != 0 {
			hits = append(hits, detect.Traversal(norm)...)
			hits = append(hits, detect.NullByte(in.Value)...)
		}
		if a&aFile != 0 {
			hits = append(hits, detect.FileAccess(norm)...)
		}
		if rs != nil {
			hits = append(hits, rs.Match(in, norm)...)
		}
		for _, h := range hits {
			if h.PL > e.cfg.Paranoia {
				continue
			}
			res.Score += h.Score
			res.Findings = append(res.Findings, Finding{
				RuleID: h.ID, Category: h.Category, Message: h.Msg, Score: h.Score,
				Location: in.Location, Name: in.Name, Sample: sample(in.Value),
			})
		}
	}
	res.Blocked = res.Score >= e.cfg.Threshold
	return res
}

func sample(s string) string {
	const n = 120
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// parseDiffID gives each parser-differential code a stable 7xxx rule id.
var parseDiffIDs = map[string]int{
	"content-type-duplicate": 7001, "content-type-malformed": 7002, "content-type-mismatch": 7003, "body-charset": 7004,
	"body-invalid-utf8": 7005, "json-dup-key": 7101, "json-case-dup-key": 7102, "json-trailing-data": 7103,
	"json-nonstandard": 7104, "json-bom": 7105, "multipart-boundary-ambiguous": 7201, "multipart-boundary-prefix": 7202,
	"multipart-no-boundary": 7203, "multipart-parser-disagree": 7204, "multipart-unterminated": 7205,
	"multipart-lf-line-endings": 7206, "multipart-after-close": 7207, "multipart-dup-param": 7208,
	"multipart-dup-filename": 7209, "multipart-filename-conflict": 7210, "form-semicolon-separator": 7301,
	"form-bad-escape": 7302, "query-semicolon-separator": 7303, "query-bad-escape": 7304,
}

func parseDiffID(code string) int {
	if id, ok := parseDiffIDs[code]; ok {
		return id
	}
	return 7999
}
