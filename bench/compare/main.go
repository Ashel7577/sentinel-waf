// Command compare runs Sentinel WAF and OWASP Coraza + Core Rule Set (the
// open-source industry baseline, a Go port of ModSecurity) side by side on
// exactly the same HTTP requests, built from the same corpora, in the same
// process. Both are wrapped as real net/http middleware, so request parsing
// is included in the measured cost for both.
//
//	go run . -corpus ../../eval/corpus,../../eval/external -paranoia 1
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"

	"github.com/Ashel7577/sentinel-waf/internal/waf"
)

type placement struct {
	name  string
	build func(p string) *http.Request
}

func req(method, target, ct string, body []byte) *http.Request {
	r := httptest.NewRequest(method, target, bytes.NewReader(body))
	if ct != "" {
		r.Header.Set("Content-Type", ct)
	}
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36")
	r.Header.Set("Accept", "text/html,application/json")
	r.Host = "localhost"
	return r
}

var placements = []placement{
	{"query", func(p string) *http.Request { return req("GET", "/search?q="+url.QueryEscape(p), "", nil) }},
	{"form", func(p string) *http.Request {
		return req("POST", "/login", "application/x-www-form-urlencoded", []byte("username="+url.QueryEscape(p)+"&password=x"))
	}},
	{"json", func(p string) *http.Request {
		b, _ := json.Marshal(map[string]any{"comment": p, "rating": 5})
		return req("POST", "/api/comments", "application/json", b)
	}},
	{"header", func(p string) *http.Request {
		r := req("GET", "/", "", nil)
		r.Header.Set("X-Api-Version", strings.NewReplacer("\r", " ", "\n", " ").Replace(p))
		return r
	}},
}

type contender struct {
	name    string
	handler http.Handler
	lat     []time.Duration
}

// blocked serves the request and reports whether it was rejected with 403.
func (c *contender) blocked(r *http.Request) bool {
	w := httptest.NewRecorder()
	start := time.Now()
	c.handler.ServeHTTP(w, r)
	c.lat = append(c.lat, time.Since(start))
	return w.Code == http.StatusForbidden
}

func main() {
	dirs := flag.String("corpus", "../../eval/corpus", "comma-separated corpus dirs (attack/*.txt, benign/*.txt)")
	pl := flag.Int("paranoia", 1, "paranoia level for both WAFs")
	maxPer := flag.Int("max", 0, "cap payloads per category (0 = all)")
	out := flag.String("out", "", "write markdown report here")
	flag.Parse()

	attacks, benign := load(*dirs, *maxPer)
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })

	// --- Sentinel: the real proxy handler minus the network hop
	engine := waf.NewEngine(waf.Config{Paranoia: *pl}, waf.DefaultRules())
	sentinel := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		if r.Body != nil {
			body, _ = readAll(r)
		}
		if engine.Inspect(waf.Extract(r, body)).Blocked {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		ok(w, r)
	})

	// --- Coraza + OWASP CRS v4, blocking mode, same paranoia level
	cw, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives("Include @coraza.conf-recommended").
		WithDirectives("Include @crs-setup.conf.example").
		WithDirectives(fmt.Sprintf(`SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d"`, *pl)).
		WithDirectives("Include @owasp_crs/*.conf").
		WithDirectives("SecRuleEngine On").
		WithDirectives("SecRequestBodyAccess On"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "coraza:", err)
		os.Exit(1)
	}
	crs := txhttp.WrapHandler(cw, ok)

	contenders := []*contender{{name: "Sentinel WAF", handler: sentinel}, {name: "Coraza + OWASP CRS v4", handler: crs}}

	cats := make([]string, 0, len(attacks))
	for c := range attacks {
		cats = append(cats, c)
	}
	sort.Strings(cats)

	type score struct{ hit, total int }
	det := map[string]map[string]*score{}     // contender -> category
	byPlace := map[string]map[string]*score{} // contender -> placement
	fp := map[string]*score{}
	fpPlace := map[string]map[string]*score{}
	for _, c := range contenders {
		det[c.name] = map[string]*score{}
		byPlace[c.name] = map[string]*score{}
		fp[c.name] = &score{}
		fpPlace[c.name] = map[string]*score{}
		for _, place := range placements {
			byPlace[c.name][place.name] = &score{}
			fpPlace[c.name][place.name] = &score{}
		}
	}
	for _, cat := range cats {
		for _, p := range attacks[cat] {
			for _, place := range placements {
				for _, c := range contenders {
					s := det[c.name][cat]
					if s == nil {
						s = &score{}
						det[c.name][cat] = s
					}
					s.total++
					bp := byPlace[c.name][place.name]
					bp.total++
					if c.blocked(place.build(p)) {
						s.hit++
						bp.hit++
					}
				}
			}
		}
	}
	for _, p := range benign {
		for _, place := range placements {
			for _, c := range contenders {
				fp[c.name].total++
				fpPlace[c.name][place.name].total++
				if c.blocked(place.build(p)) {
					fp[c.name].hit++
					fpPlace[c.name][place.name].hit++
				}
			}
		}
	}

	pct := func(s *score) string {
		if s == nil || s.total == 0 {
			return "–"
		}
		return fmt.Sprintf("%.1f%%", 100*float64(s.hit)/float64(s.total))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "## Sentinel WAF vs Coraza + OWASP CRS v4\n\nParanoia level %d · block threshold 5 (both) · %d placements per payload (query, form, JSON, header) · corpus `%s`\n\n", *pl, len(placements), *dirs)
	fmt.Fprintf(&b, "| Category | Payloads |")
	for _, c := range contenders {
		fmt.Fprintf(&b, " %s |", c.name)
	}
	fmt.Fprintf(&b, "\n|---|---|%s\n", strings.Repeat("---|", len(contenders)))
	for _, cat := range cats {
		fmt.Fprintf(&b, "| %s | %d |", cat, len(attacks[cat]))
		for _, c := range contenders {
			fmt.Fprintf(&b, " %s |", pct(det[c.name][cat]))
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "| **all attacks** | |")
	for _, c := range contenders {
		var t score
		for _, s := range det[c.name] {
			t.hit += s.hit
			t.total += s.total
		}
		fmt.Fprintf(&b, " **%s** |", pct(&t))
	}
	fmt.Fprintf(&b, "\n| **false positives** (benign) | %d |", len(benign))
	for _, c := range contenders {
		fmt.Fprintf(&b, " **%s** (%d) |", pct(fp[c.name]), fp[c.name].hit)
	}
	fmt.Fprintf(&b, "\n\n**By placement** (detection / false positives):\n\n| Placement |")
	for _, c := range contenders {
		fmt.Fprintf(&b, " %s |", c.name)
	}
	fmt.Fprintf(&b, "\n|---|%s\n", strings.Repeat("---|", len(contenders)))
	for _, place := range placements {
		fmt.Fprintf(&b, "| %s |", place.name)
		for _, c := range contenders {
			fmt.Fprintf(&b, " %s / %s |", pct(byPlace[c.name][place.name]), pct(fpPlace[c.name][place.name]))
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "| **query+form+json only** |")
	for _, c := range contenders {
		var t, f score
		for _, place := range placements[:3] {
			t.hit += byPlace[c.name][place.name].hit
			t.total += byPlace[c.name][place.name].total
			f.hit += fpPlace[c.name][place.name].hit
			f.total += fpPlace[c.name][place.name].total
		}
		fmt.Fprintf(&b, " **%s / %s** |", pct(&t), pct(&f))
	}
	b.WriteString("\n\nCRS at paranoia 1 does not inspect arbitrary custom request headers by design, which lowers its header column; the query+form+json row excludes that.")
	fmt.Fprintf(&b, "\n\n| Latency per request (in-process, parse + inspect) | mean | p50 | p99 |\n|---|---|---|---|\n")
	for _, c := range contenders {
		mean, p50, p99 := stats(c.lat)
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", c.name, mean, p50, p99)
	}
	fmt.Print(b.String())
	if *out != "" {
		os.WriteFile(*out, []byte(b.String()), 0o644)
	}
}

func stats(d []time.Duration) (string, string, string) {
	if len(d) == 0 {
		return "–", "–", "–"
	}
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	var sum time.Duration
	for _, x := range s {
		sum += x
	}
	r := func(x time.Duration) string { return x.Round(time.Microsecond).String() }
	return r(sum / time.Duration(len(s))), r(s[len(s)/2]), r(s[int(0.99*float64(len(s)-1))])
}

func readAll(r *http.Request) ([]byte, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(r.Body)
	r.Body.Close()
	return buf.Bytes(), err
}

func load(dirs string, max int) (map[string][]string, []string) {
	attacks := map[string][]string{}
	var benign []string
	for _, d := range strings.Split(dirs, ",") {
		files, _ := filepath.Glob(filepath.Join(d, "attack", "*.txt"))
		for _, f := range files {
			cat := strings.TrimSuffix(filepath.Base(f), ".txt")
			attacks[cat] = append(attacks[cat], readLines(f)...)
		}
		files, _ = filepath.Glob(filepath.Join(d, "benign", "*.txt"))
		for _, f := range files {
			benign = append(benign, readLines(f)...)
		}
	}
	if max > 0 {
		for c, ps := range attacks {
			attacks[c] = sample(ps, max)
		}
		benign = sample(benign, max*4)
	}
	return attacks, benign
}

// sample takes an evenly spaced, deterministic subset.
func sample(ps []string, n int) []string {
	if len(ps) <= n {
		return ps
	}
	out := make([]string, 0, n)
	step := float64(len(ps)) / float64(n)
	for i := 0; i < n; i++ {
		out = append(out, ps[int(float64(i)*step)])
	}
	return out
}

func readLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if l := strings.TrimRight(sc.Text(), "\r"); strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}
