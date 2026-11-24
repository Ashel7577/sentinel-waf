// Package detect contains the built-in attack analysers. Every analyser takes
// an already-normalized value and returns zero or more Hits.
package detect

// Severity scores follow the OWASP CRS anomaly-scoring convention so results
// are comparable: a single critical hit reaches the default block threshold.
const (
	Critical = 5
	Error    = 4
	Warning  = 3
	Notice   = 2
)

// Hit is one detector match.
type Hit struct {
	ID       int    // stable rule id (1xxx sqli, 2xxx xss, 3xxx cmdi, 4xxx traversal, 9xxx rule file)
	Category string // sqli, xss, cmdi, traversal, ...
	Score    int    // anomaly score contribution
	PL       int    // paranoia level the hit belongs to (1 = always on)
	Msg      string
}

type hitSet struct {
	hits []Hit
	seen map[int]bool
}

func (h *hitSet) add(id int, cat string, score, pl int, msg string) {
	if h.seen == nil {
		h.seen = make(map[int]bool, 4)
	}
	if h.seen[id] {
		return
	}
	h.seen[id] = true
	h.hits = append(h.hits, Hit{ID: id, Category: cat, Score: score, PL: pl, Msg: msg})
}
