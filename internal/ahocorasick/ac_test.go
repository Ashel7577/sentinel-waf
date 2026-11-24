package ahocorasick

import (
	"sort"
	"strings"
	"testing"
)

func found(m *Matcher, s string) []int {
	set := map[int]bool{}
	m.Each(s, func(id int) { set[id] = true })
	var out []int
	for id := range set {
		out = append(out, id)
	}
	sort.Ints(out)
	return out
}

func TestMatcher(t *testing.T) {
	m := New([]string{"he", "she", "his", "hers", "${", "://"})
	cases := map[string][]int{
		"ushers":              {0, 1, 3},
		"this":                {2},
		"x ${jndi:ldap://a}":  {4, 5},
		"nothing here at all": {0}, // "here" contains "he"
		"":                    nil,
	}
	for in, want := range cases {
		if got := found(m, in); !equal(got, want) {
			t.Errorf("%q: got %v want %v", in, got, want)
		}
	}
}

// Cross-check against strings.Contains on many overlapping patterns.
func TestAgainstNaive(t *testing.T) {
	pats := []string{"a", "ab", "bab", "bc", "bca", "c", "caa", "aaaa", "cab"}
	m := New(pats)
	inputs := []string{"abccab", "aaaaaa", "bcabca", "xyz", "cacbcbab"}
	for _, in := range inputs {
		got := found(m, in)
		var want []int
		for i, p := range pats {
			if strings.Contains(in, p) {
				want = append(want, i)
			}
		}
		if !equal(got, want) {
			t.Errorf("%q: got %v want %v", in, got, want)
		}
	}
}

func equal(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func BenchmarkEach(b *testing.B) {
	m := New([]string{"${", "{{", "<?", "://", "169.254", "__proto__", "<!", "$where", "#{", "%{"})
	s := strings.Repeat("the quick brown fox jumps over the lazy dog ", 10)
	b.SetBytes(int64(len(s)))
	for i := 0; i < b.N; i++ {
		m.Each(s, func(int) {})
	}
}
