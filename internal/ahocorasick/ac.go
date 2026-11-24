// Package ahocorasick implements a byte-level Aho-Corasick automaton compiled
// to a full DFA, used as a literal prefilter: one linear pass over a value
// reports every rule whose required literal appears, so expensive regexes only
// run on the few rules that can possibly match.
package ahocorasick

// Matcher is immutable after New and safe for concurrent use.
type Matcher struct {
	delta [][256]int32 // DFA transitions (goto + failure links folded in)
	out   [][]int32    // pattern ids recognised in each state
}

// New compiles patterns (matched case-sensitively on raw bytes; lower-case
// both sides beforehand for case-insensitive search).
func New(patterns []string) *Matcher {
	m := &Matcher{}
	m.delta = append(m.delta, [256]int32{})
	m.out = append(m.out, nil)
	for i := range m.delta[0] {
		m.delta[0][i] = -1
	}

	// 1. trie
	for id, p := range patterns {
		if p == "" {
			continue
		}
		s := int32(0)
		for i := 0; i < len(p); i++ {
			c := p[i]
			if m.delta[s][c] < 0 {
				var row [256]int32
				for k := range row {
					row[k] = -1
				}
				m.delta = append(m.delta, row)
				m.out = append(m.out, nil)
				m.delta[s][c] = int32(len(m.delta) - 1)
			}
			s = m.delta[s][c]
		}
		m.out[s] = append(m.out[s], int32(id))
	}

	// 2. BFS: failure links, folded into a complete transition table
	fail := make([]int32, len(m.delta))
	queue := make([]int32, 0, len(m.delta))
	for c := 0; c < 256; c++ {
		if t := m.delta[0][c]; t > 0 {
			fail[t] = 0
			queue = append(queue, t)
		} else {
			m.delta[0][c] = 0
		}
	}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		m.out[s] = append(m.out[s], m.out[fail[s]]...)
		for c := 0; c < 256; c++ {
			t := m.delta[s][c]
			if t < 0 {
				m.delta[s][c] = m.delta[fail[s]][c]
				continue
			}
			fail[t] = m.delta[fail[s]][c]
			queue = append(queue, t)
		}
	}
	return m
}

// Each calls fn for every pattern occurrence in s (a pattern may be reported
// more than once).
func (m *Matcher) Each(s string, fn func(id int)) {
	st := int32(0)
	for i := 0; i < len(s); i++ {
		st = m.delta[st][s[i]]
		for _, id := range m.out[st] {
			fn(int(id))
		}
	}
}

// States returns the automaton size (for diagnostics).
func (m *Matcher) States() int { return len(m.delta) }
