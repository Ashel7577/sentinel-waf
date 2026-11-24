package waf

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/Ashel7577/sentinel-waf/internal/ahocorasick"
	"github.com/Ashel7577/sentinel-waf/internal/detect"
)

//go:embed rules.json
var defaultRules []byte

// DefaultRules returns the embedded rule set.
func DefaultRules() *RuleSet {
	rs, err := ParseRules(defaultRules)
	if err != nil {
		panic("embedded rules.json is invalid: " + err.Error())
	}
	return rs
}

// Rule is a signature loaded from a JSON rule file. Rules complement the
// built-in analysers with signatures for attack classes that are naturally
// pattern-shaped (Log4Shell, SSTI, XXE, SSRF, scanners...). They can be
// edited and hot-reloaded without restarting the WAF.
type Rule struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
	Pattern  string `json:"pattern"`
	Score    int    `json:"score"`
	Paranoia int    `json:"paranoia,omitempty"`
	// Targets restricts the rule to input locations ("query", "header",
	// "header:user-agent", "key", ...). Empty means every location.
	Targets []string `json:"targets,omitempty"`
	// Raw matches against the undecoded value (for CRLF and similar).
	Raw bool `json:"raw,omitempty"`
	// Prefilter lists literals of which at least one must occur in the
	// (lower-case) value for the regex to be worth running. Every match of
	// Pattern must contain one of them; TestPrefiltersAreSound checks this.
	Prefilter []string `json:"prefilter,omitempty"`

	re *regexp.Regexp
}

// RuleSet is an immutable compiled set of rules.
type RuleSet struct {
	Rules []*Rule

	ac       *ahocorasick.Matcher
	litRules [][]int // literal id -> indexes of rules requiring it
	always   []int   // non-raw rules without a prefilter
}

// ParseRules compiles a JSON rule file.
func ParseRules(data []byte) (*RuleSet, error) {
	var rules []*Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	rs := &RuleSet{Rules: rules}
	ids := map[int]bool{}
	var lits []string
	litIndex := map[string]int{}
	for i, r := range rules {
		if ids[r.ID] {
			return nil, fmt.Errorf("duplicate rule id %d", r.ID)
		}
		ids[r.ID] = true
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", r.ID, err)
		}
		r.re = re
		if r.Paranoia == 0 {
			r.Paranoia = 1
		}
		if r.Score == 0 {
			r.Score = detect.Critical
		}
		for k, p := range r.Prefilter {
			r.Prefilter[k] = strings.ToLower(p)
		}
		if r.Raw {
			continue // raw rules check their prefilter on the raw value
		}
		if len(r.Prefilter) == 0 {
			rs.always = append(rs.always, i)
			continue
		}
		for _, p := range r.Prefilter {
			id, ok := litIndex[p]
			if !ok {
				id = len(lits)
				litIndex[p] = id
				lits = append(lits, p)
				rs.litRules = append(rs.litRules, nil)
			}
			rs.litRules[id] = append(rs.litRules[id], i)
		}
	}
	if len(lits) > 0 {
		rs.ac = ahocorasick.New(lits)
	}
	return rs, nil
}

func (r *Rule) applies(in Input) bool {
	if len(r.Targets) == 0 {
		return true
	}
	for _, t := range r.Targets {
		loc, name, hasName := strings.Cut(t, ":")
		locOK := loc == in.Location ||
			(loc == locHeader && in.Location == locStdHdr) ||
			(loc == "path" && in.Location == locSegment)
		if locOK && (!hasName || name == in.Name) {
			return true
		}
	}
	return false
}

// Match runs all applicable rules on an input. A single Aho-Corasick pass
// over the normalized value selects the candidate rules.
func (rs *RuleSet) Match(in Input, normalized string) []detect.Hit {
	var stack [64]bool
	cand := stack[:0]
	if len(rs.Rules) <= len(stack) {
		cand = stack[:len(rs.Rules)]
	} else {
		cand = make([]bool, len(rs.Rules))
	}
	for _, i := range rs.always {
		cand[i] = true
	}
	if rs.ac != nil {
		rs.ac.Each(normalized, func(id int) {
			for _, ri := range rs.litRules[id] {
				cand[ri] = true
			}
		})
	}

	var hits []detect.Hit
	lowerRaw, haveLower := "", false
	for i, r := range rs.Rules {
		if r.Raw {
			if !r.applies(in) {
				continue
			}
			if len(r.Prefilter) > 0 {
				if !haveLower {
					lowerRaw, haveLower = strings.ToLower(in.Value), true
				}
				if !containsAny(lowerRaw, r.Prefilter) {
					continue
				}
			}
			if r.re.MatchString(in.Value) {
				hits = append(hits, hit(r))
			}
			continue
		}
		if !cand[i] || !r.applies(in) {
			continue
		}
		if r.re.MatchString(normalized) {
			hits = append(hits, hit(r))
		}
	}
	return hits
}

func hit(r *Rule) detect.Hit {
	return detect.Hit{ID: r.ID, Category: r.Category, Score: r.Score, PL: r.Paranoia, Msg: r.Name}
}

func containsAny(s string, subs []string) bool {
	for _, p := range subs {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}
