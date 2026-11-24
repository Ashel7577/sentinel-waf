// Command eval measures detection rate and false-positive rate against payload
// corpora, placing every payload in several parts of an HTTP request.
//
// Corpus layout (one payload per line):
//
//	<dir>/attack/<category>.txt
//	<dir>/benign/<anything>.txt
//
// By default requests are inspected in-process (fast, also reports engine
// latency). With -url they are sent over HTTP to a running WAF and a 403
// counts as blocked.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Ashel7577/sentinel-waf/internal/waf"
)

type placement struct {
	name  string
	build func(base, payload string) (*http.Request, []byte)
}

var placements = []placement{
	{"query", func(base, p string) (*http.Request, []byte) {
		return mk("GET", base+"/search?q="+url.QueryEscape(p), "", nil), nil
	}},
	{"form", func(base, p string) (*http.Request, []byte) {
		b := []byte("username=" + url.QueryEscape(p) + "&password=x")
		return mk("POST", base+"/login", "application/x-www-form-urlencoded", b), b
	}},
	{"json", func(base, p string) (*http.Request, []byte) {
		b, _ := json.Marshal(map[string]any{"comment": p, "rating": 5})
		return mk("POST", base+"/api/comments", "application/json", b), b
	}},
	{"header", func(base, p string) (*http.Request, []byte) {
		r := mk("GET", base+"/", "", nil)
		r.Header.Set("X-Api-Version", strings.NewReplacer("\r", " ", "\n", " ").Replace(p))
		return r, nil
	}},
}

func mk(method, target, ct string, body []byte) *http.Request {
	var r *http.Request
	if strings.HasPrefix(target, "http") {
		r, _ = http.NewRequest(method, target, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, bytes.NewReader(body))
	}
	if ct != "" {
		r.Header.Set("Content-Type", ct)
	}
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) sentinel-eval")
	return r
}

type tally struct{ hit, total int }

func (t tally) pct() float64 {
	if t.total == 0 {
		return 0
	}
	return 100 * float64(t.hit) / float64(t.total)
}

func main() {
	dirs := flag.String("corpus", "eval/corpus", "comma-separated corpus directories")
	target := flag.String("url", "", "send requests to a running WAF at this base URL instead of in-process")
	out := flag.String("out", "", "write a markdown report here")
	misses := flag.String("misses", "", "write missed attacks / false positives here")
	threshold := flag.Int("threshold", 5, "block threshold (in-process mode)")
	paranoia := flag.Int("paranoia", 1, "paranoia level (in-process mode)")
	flag.Parse()

	attacks := map[string][]string{}
	var benign []string
	for _, d := range strings.Split(*dirs, ",") {
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
	if len(attacks) == 0 {
		fmt.Fprintln(os.Stderr, "no corpus found")
		os.Exit(1)
	}

	engine := waf.NewEngine(waf.Config{Threshold: *threshold, Paranoia: *paranoia}, waf.DefaultRules())
	client := &http.Client{Timeout: 10 * time.Second}
	var durations []time.Duration

	blocked := func(pl placement, payload string) bool {
		if *target != "" {
			r, _ := pl.build(strings.TrimRight(*target, "/"), payload)
			resp, err := client.Do(r)
			if err != nil {
				return false
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			return resp.StatusCode == http.StatusForbidden
		}
		r, body := pl.build("", payload)
		start := time.Now()
		res := engine.Inspect(waf.Extract(r, body))
		durations = append(durations, time.Since(start))
		return res.Blocked
	}

	var missLog strings.Builder
	cats := make([]string, 0, len(attacks))
	for c := range attacks {
		cats = append(cats, c)
	}
	sort.Strings(cats)

	det := map[string]map[string]*tally{}
	var detAll tally
	for _, c := range cats {
		det[c] = map[string]*tally{}
		for _, pl := range placements {
			t := &tally{}
			for _, p := range attacks[c] {
				t.total++
				if blocked(pl, p) {
					t.hit++
				} else {
					fmt.Fprintf(&missLog, "MISS\t%s\t%s\t%s\n", c, pl.name, p)
				}
			}
			det[c][pl.name] = t
			detAll.hit += t.hit
			detAll.total += t.total
		}
	}

	fp := map[string]*tally{}
	var fpAll tally
	for _, pl := range placements {
		t := &tally{}
		for _, p := range benign {
			t.total++
			if blocked(pl, p) {
				t.hit++
				fmt.Fprintf(&missLog, "FP\t%s\t%s\n", pl.name, p)
			}
		}
		fp[pl.name] = t
		fpAll.hit += t.hit
		fpAll.total += t.total
	}

	var rep strings.Builder
	mode := "in-process engine"
	if *target != "" {
		mode = "HTTP against " + *target
	}
	fmt.Fprintf(&rep, "## Detection results\n\nMode: %s · threshold %d · paranoia %d · corpus: `%s`\n\n", mode, *threshold, *paranoia, *dirs)
	fmt.Fprintf(&rep, "| Category | Payloads |")
	for _, pl := range placements {
		fmt.Fprintf(&rep, " %s |", pl.name)
	}
	fmt.Fprintf(&rep, "\n|---|---|%s\n", strings.Repeat("---|", len(placements)))
	for _, c := range cats {
		fmt.Fprintf(&rep, "| %s | %d |", c, len(attacks[c]))
		for _, pl := range placements {
			fmt.Fprintf(&rep, " %.1f%% |", det[c][pl.name].pct())
		}
		rep.WriteString("\n")
	}
	fmt.Fprintf(&rep, "| **benign (false positives)** | %d |", len(benign))
	for _, pl := range placements {
		fmt.Fprintf(&rep, " %.2f%% |", fp[pl.name].pct())
	}
	fmt.Fprintf(&rep, "\n\n**Overall:** detection %.2f%% (%d/%d) · false positives %.2f%% (%d/%d)\n",
		detAll.pct(), detAll.hit, detAll.total, fpAll.pct(), fpAll.hit, fpAll.total)

	if len(durations) > 0 {
		sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
		var sum time.Duration
		for _, d := range durations {
			sum += d
		}
		q := func(f float64) time.Duration { return durations[int(f*float64(len(durations)-1))] }
		fmt.Fprintf(&rep, "\n**Engine latency per request** (parse + inspect, %d requests): mean %s · p50 %s · p99 %s · max %s\n",
			len(durations), (sum / time.Duration(len(durations))).Round(time.Microsecond/10),
			q(0.5).Round(time.Microsecond/10), q(0.99).Round(time.Microsecond/10), durations[len(durations)-1].Round(time.Microsecond/10))
	}

	fmt.Print(rep.String())
	if *out != "" {
		os.WriteFile(*out, []byte(rep.String()), 0o644)
	}
	if *misses != "" {
		os.WriteFile(*misses, []byte(missLog.String()), 0o644)
	}
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
