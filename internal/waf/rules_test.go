package waf

import (
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Ashel7577/sentinel-waf/internal/normalize"
)

// A prefilter is only an optimisation if it never hides a real match: for
// every corpus line a rule's regex matches, one of its literals must occur.
func TestPrefiltersAreSound(t *testing.T) {
	rs := DefaultRules()
	inputs := lines(t, "../../eval/corpus/*/*.txt")
	for _, r := range rs.Rules {
		if len(r.Prefilter) == 0 {
			continue
		}
		for _, raw := range inputs {
			v := normalize.Value(raw)
			if r.Raw {
				v = raw
			}
			if r.re.MatchString(v) && !containsAny(strings.ToLower(v), r.Prefilter) {
				t.Errorf("rule %d matches %q but none of its prefilters %q occur", r.ID, raw, r.Prefilter)
			}
		}
	}
}

// Prints the cost of each rule's regex over the benign corpus when
// SENTINEL_RULE_COST=1 (diagnostics, not a pass/fail test).
func TestRuleCost(t *testing.T) {
	if os.Getenv("SENTINEL_RULE_COST") == "" {
		t.Skip("set SENTINEL_RULE_COST=1")
	}
	rs := DefaultRules()
	inputs := lines(t, "../../eval/corpus/benign/*.txt")
	type cost struct {
		id  int
		d   time.Duration
		ran int
	}
	var costs []cost
	for _, r := range rs.Rules {
		c := cost{id: r.ID}
		for _, raw := range inputs {
			v := normalize.Value(raw)
			if len(r.Prefilter) > 0 && !containsAny(strings.ToLower(v), r.Prefilter) {
				continue
			}
			start := time.Now()
			for k := 0; k < 50; k++ {
				r.re.MatchString(v)
			}
			c.d += time.Since(start)
			c.ran++
		}
		costs = append(costs, c)
	}
	sort.Slice(costs, func(i, j int) bool { return costs[i].d > costs[j].d })
	for _, c := range costs {
		t.Logf("rule %d: %v over %d/%d inputs", c.id, c.d/50, c.ran, len(inputs))
	}
}
