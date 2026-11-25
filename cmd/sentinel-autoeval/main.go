// Command sentinel-autoeval is the autonomous WAF evaluation engine. It drives
// the WAF from its own responses: it seeds attacks, keeps the ones the WAF
// catches, mutates them searching for an evasion, confirms against a demo
// backend whether a payload actually reached the app, auto-tunes the operating
// point, writes a verified evidence chain, keeps a run history (the tuning
// loop), and renders a print-ready report.
//
//	go run ./cmd/sentinel-autoeval -out autoeval-out -label "Run 1"
//	go run ./cmd/sentinel-autoeval -out autoeval-out -render-only -shots "a.png|Title|Caption"
package main

import (
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
	"strings"
	"time"

	"github.com/Ashel7577/sentinel-waf/internal/evidence"
	"github.com/Ashel7577/sentinel-waf/internal/hrclock"
	"github.com/Ashel7577/sentinel-waf/internal/redteam"
	"github.com/Ashel7577/sentinel-waf/internal/testapp"
	"github.com/Ashel7577/sentinel-waf/internal/waf"
)

func main() {
	out := flag.String("out", "autoeval-out", "output directory")
	pl := flag.Int("paranoia", 1, "paranoia level under test")
	thr := flag.Int("threshold", 5, "block threshold under test")
	gens := flag.Int("generations", 4, "max adaptive generations")
	maxTrials := flag.Int("max-trials", 6000, "max attack requests")
	label := flag.String("label", "", "name of this run in the history (empty: not recorded)")
	note := flag.String("note", "", "what changed before this run (history note)")
	replay := flag.String("replay", "", "after the campaign, replay its attacks and benign traffic through a live Sentinel proxy at this URL (feeds the live dashboard)")
	shots := flag.String("shots", "", "screenshots to embed: path|title|caption;path|title|caption")
	failOnBypass := flag.Bool("fail-on-bypass", false, "exit 2 if the search finds any bypass (CI regression gate)")
	renderOnly := flag.Bool("render-only", false, "re-render report.html from report.json + history + -shots without re-running")
	flag.Parse()
	must(os.MkdirAll(*out, 0o755))
	histPath := filepath.Join(*out, "history.jsonl")
	evPath := filepath.Join(*out, "evidence.jsonl")

	if *renderOnly {
		var rep redteam.Report
		data, err := os.ReadFile(filepath.Join(*out, "report.json"))
		must(err)
		must(json.Unmarshal(data, &rep))
		rep.History = loadHistory(histPath)
		rep.Shots = parseShots(*shots)
		recs, _ := evidence.ReadFile(evPath)
		chain := evidence.Verify(recs)
		writeHTML(*out, &rep, chain)
		fmt.Printf("report: %s (%d screenshots, %d history runs)\n", filepath.Join(*out, "report.html"), len(rep.Shots), len(rep.History))
		return
	}

	app := testapp.Handler()
	benign := loadBenign()

	target := func(paranoia, threshold int) redteam.Target {
		eng := waf.NewEngine(waf.Config{Threshold: threshold, Paranoia: paranoia}, waf.DefaultRules())
		return redteam.Target{
			Inspect: func(rq redteam.Request) redteam.Verdict {
				hr, body := build(rq)
				inputs := waf.Extract(hr, body)
				t0 := hrclock.Now() // high-resolution clock (QPC on Windows)
				res := eng.Inspect(inputs)
				return redteam.Verdict{Score: res.Score, Blocked: res.Blocked, Cats: res.Categories(), LatencyNS: hrclock.Now() - t0}
			},
			Lands: func(rq redteam.Request) []string {
				hr, _ := build(rq)
				rec := httptest.NewRecorder()
				app.ServeHTTP(rec, hr)
				var got testapp.Received
				_ = json.Unmarshal(rec.Body.Bytes(), &got)
				return got.Values
			},
		}
	}

	fmt.Printf("==> autonomous evaluation: paranoia %d, threshold %d, up to %d generations\n", *pl, *thr, *gens)
	rep := redteam.Run(target(*pl, *thr), redteam.Options{
		MaxGenerations: *gens, MaxTrials: *maxTrials, Benign: benign,
		Log: func(s string) { fmt.Println("   ", s) },
	})

	fmt.Println("==> tuning operating point across paranoia levels")
	rep.Tuning = redteam.Tune(
		[]struct{ Paranoia, Threshold int }{{1, *thr}, {2, *thr}, {3, *thr}, {4, *thr}},
		target, benign, 0.005)

	// verified evidence chain: every bypass + a sample of blocked attacks
	_ = os.Remove(evPath)
	vault, err := evidence.Open(evPath)
	must(err)
	eng := waf.NewEngine(waf.Config{Threshold: *thr, Paranoia: *pl}, waf.DefaultRules())
	blk := 0
	for _, tr := range rep.Trials() {
		record := tr.Bypass
		if !record && tr.Blocked && tr.Landed && blk < 60 {
			record = true
			blk++
		}
		if !record {
			continue
		}
		hr, body := buildFromTrial(tr)
		res := eng.Inspect(waf.Extract(hr, body))
		fs := make([]evidence.Finding, 0, len(res.Findings))
		for _, f := range res.Findings {
			fs = append(fs, evidence.Finding{RuleID: f.RuleID, Category: f.Category, Message: f.Message, Score: f.Score, Location: f.Location, Name: f.Name, Sample: f.Sample})
		}
		action := "blocked"
		if tr.Bypass {
			action = "flagged" // reached the app without being blocked: evidence of the gap
		}
		if _, err := vault.Capture(hr, body, reqID(tr), "127.0.0.1", action, res.Score, *thr, fs, waf.Version); err != nil {
			fmt.Fprintln(os.Stderr, "evidence:", err)
		}
	}
	vault.Close()
	recs, _ := evidence.ReadFile(evPath)
	chain := evidence.Verify(recs)

	// history: the tuning loop
	if *label != "" {
		appendHistory(histPath, rep.Summary(*label, *note))
	}
	rep.History = loadHistory(histPath)
	rep.Shots = parseShots(*shots)

	j, _ := json.MarshalIndent(rep, "", "  ")
	must(os.WriteFile(filepath.Join(*out, "report.json"), j, 0o644))
	writeHTML(*out, rep, chain)

	fmt.Printf("\n==> result: %.1f%% detection of %d landed attacks · %d bypass(es) · %.2f%% false positives\n",
		rep.DetectionRate()*100, rep.Landed, len(rep.Bypasses), rep.Benign.FPRate*100)
	fmt.Printf("    inspection p50 %s · p99 %s over %d requests\n", usCLI(rep.Latency.P50), usCLI(rep.Latency.P99), rep.Latency.Samples)
	rec := recommended(rep)
	fmt.Printf("    recommended operating point: paranoia %d (detection %.1f%%, FP %.2f%%)\n", rec.Paranoia, rec.DetectionRate*100, rec.FPRate*100)
	fmt.Printf("    evidence: %d records, chain %s\n", chain.Records, okStr(chain.OK))

	if *replay != "" {
		n, blocked := replayLive(*replay, rep, benign)
		fmt.Printf("==> replayed %d requests through the live proxy %s (%d blocked)\n", n, *replay, blocked)
	}
	fmt.Printf("    report: %s\n", filepath.Join(*out, "report.html"))
	if *failOnBypass && len(rep.Bypasses) > 0 {
		fmt.Fprintf(os.Stderr, "autoeval: %d confirmed bypass(es)\n", len(rep.Bypasses))
		os.Exit(2)
	}
}

func writeHTML(out string, rep *redteam.Report, chain evidence.Report) {
	doc := rep.HTMLReport("Sentinel WAF — Autonomous Evaluation Report", waf.Version, chain.HeadHash, chain.OK, chain.Records)
	must(os.WriteFile(filepath.Join(out, "report.html"), []byte(doc), 0o644))
}

func parseShots(spec string) []redteam.Shot {
	var out []redteam.Shot
	for _, s := range strings.Split(spec, ";") {
		f := strings.SplitN(s, "|", 3)
		if len(f) == 3 && f[0] != "" {
			out = append(out, redteam.Shot{Path: f[0], Title: f[1], Caption: f[2]})
		}
	}
	return out
}

func loadHistory(path string) []redteam.RunSummary {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []redteam.RunSummary
	for _, l := range strings.Split(string(data), "\n") {
		var s redteam.RunSummary
		if json.Unmarshal([]byte(l), &s) == nil && s.Label != "" {
			out = append(out, s)
		}
	}
	return out
}

func appendHistory(path string, s redteam.RunSummary) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	must(err)
	defer f.Close()
	b, _ := json.Marshal(s)
	_, err = f.Write(append(b, '\n'))
	must(err)
}

// replayLive sends the campaign's landed attacks, interleaved with benign
// traffic, through a running Sentinel proxy, paced so the live dashboard and
// evidence vault show the campaign.
func replayLive(base string, rep *redteam.Report, benign []string) (int, int) {
	cl := &http.Client{Timeout: 5 * time.Second}
	send := func(rq redteam.Request) int {
		req, err := http.NewRequest(rq.Method, strings.TrimRight(base, "/")+rq.Path, bytes.NewReader(rq.Body))
		if err != nil {
			return 0
		}
		req.Header.Set("User-Agent", "sentinel-autoeval/1.0")
		for _, kv := range rq.Headers {
			req.Header.Add(kv[0], kv[1])
		}
		resp, err := cl.Do(req)
		if err != nil {
			return 0
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	n, blocked, bi := 0, 0, 0
	seen := map[string]bool{}
	for _, tr := range rep.Trials() {
		if !tr.Landed || n >= 240 {
			continue
		}
		k := tr.Placement + tr.Payload
		if seen[k] {
			continue
		}
		seen[k] = true
		for _, pl := range placementByName(tr.Placement) {
			if send(pl.Build(tr.Payload)) == 403 {
				blocked++
			}
			n++
		}
		for j := 0; j < 2 && bi < len(benign); j++ {
			send(redteam.Request{Method: "GET", Path: "/search?q=" + url.QueryEscape(benign[bi])})
			bi++
			n++
		}
		time.Sleep(60 * time.Millisecond)
	}
	return n, blocked
}

func build(rq redteam.Request) (*http.Request, []byte) {
	body := rq.Body
	hr := httptest.NewRequest(rq.Method, "http://localhost"+rq.Path, bytes.NewReader(body))
	hr.Header.Del("Content-Type")
	for _, kv := range rq.Headers {
		hr.Header.Add(kv[0], kv[1])
	}
	hr.Body = io.NopCloser(bytes.NewReader(body))
	hr.ContentLength = int64(len(body))
	return hr, body
}

func buildFromTrial(t redteam.Trial) (*http.Request, []byte) {
	for _, pl := range placementByName(t.Placement) {
		return build(pl.Build(t.Payload))
	}
	return build(redteam.Request{Method: "GET", Path: "/search?q=" + url.QueryEscape(t.Payload)})
}

func placementByName(name string) []redteam.Placement {
	for _, pl := range redteam.Placements() {
		if pl.Name == name {
			return []redteam.Placement{pl}
		}
	}
	return nil
}

func reqID(t redteam.Trial) string {
	s := string(t.Class) + t.Placement + t.Mutator + t.Payload
	var h uint64 = 1469598103934665603
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return fmt.Sprintf("%016x", h)
}

func loadBenign() []string {
	data, err := os.ReadFile(filepath.Join("eval", "corpus", "benign", "general.txt"))
	if err != nil {
		return []string{"hello world", "O'Reilly books", "select a size", "where is my order", "2 + 2 = 4"}
	}
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
		if len(out) >= 400 {
			break
		}
	}
	return out
}

func recommended(r *redteam.Report) redteam.TunePoint {
	for _, tp := range r.Tuning {
		if tp.Recommended {
			return tp
		}
	}
	if len(r.Tuning) > 0 {
		return r.Tuning[0]
	}
	return redteam.TunePoint{}
}

func usCLI(ns int64) string {
	if ns >= 1_000_000 {
		return fmt.Sprintf("%.2fms", float64(ns)/1e6)
	}
	return fmt.Sprintf("%.1fµs", float64(ns)/1000)
}

func okStr(b bool) string {
	if b {
		return "VERIFIED"
	}
	return "BROKEN"
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "autoeval:", err)
		os.Exit(1)
	}
}
