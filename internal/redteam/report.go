package redteam

import (
	"encoding/base64"
	"fmt"
	"html"
	"os"
	"strings"
	"time"
)

// Shot is a screenshot embedded in the report.
type Shot struct {
	Path, Title, Caption string
}

// RunSummary is one campaign in the engine's history (the tuning loop).
type RunSummary struct {
	Label     string    `json:"label"`
	Time      time.Time `json:"time"`
	Trials    int       `json:"trials"`
	Landed    int       `json:"landed"`
	Detection float64   `json:"detection"`
	Bypasses  int       `json:"bypasses"`
	FPRate    float64   `json:"fp_rate"`
	Samples   []string  `json:"bypass_samples,omitempty"`
	Note      string    `json:"note,omitempty"`
}

// Summary condenses this report into a history entry.
func (r *Report) Summary(label, note string) RunSummary {
	s := RunSummary{Label: label, Time: time.Now().UTC(), Trials: r.TrialCount, Landed: r.Landed,
		Detection: r.DetectionRate(), Bypasses: len(r.Bypasses), FPRate: r.Benign.FPRate, Note: note}
	seen := map[string]bool{}
	for _, b := range r.Bypasses {
		k := string(b.Class) + " · " + b.Placement + " · " + b.Payload
		if !seen[k] && len(s.Samples) < 6 {
			seen[k] = true
			s.Samples = append(s.Samples, k)
		}
	}
	return s
}

// HTMLReport renders a print-ready evidence report. r.Shots are embedded as
// figures and r.History as the tuning-loop timeline. evidenceHead/evidenceOK
// describe the verified evidence chain the campaign wrote.
func (r *Report) HTMLReport(title, wafVersion, evidenceHead string, evidenceOK bool, evidenceRecords int) string {
	var b strings.Builder
	p := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	det := r.DetectionRate()
	p(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>%s</title><style>%s</style></head><body>`, html.EscapeString(title), reportCSS)
	p(`<header><div><h1>%s</h1><div class="sub">Autonomous WAF evaluation · generated %s</div></div><div class="stamp %s">%s</div></header>`,
		html.EscapeString(title), time.Now().UTC().Format("2006-01-02 15:04 MST"),
		boolClass(len(r.Bypasses) == 0 && r.Benign.FPRate == 0), headline(r))

	// summary tiles
	p(`<section class="tiles">`)
	tile(&b, "Attacks evaluated", comma(r.TrialCount), fmt.Sprintf("%d generations of adaptive search", r.Generations))
	tile(&b, "Reached the app", comma(r.Landed), "payloads that landed on a real parameter")
	tile(&b, "Detection rate", pctf(det), fmt.Sprintf("%s of landed attacks blocked", comma(r.Blocked)))
	tile(&b, "Confirmed bypasses", comma(len(r.Bypasses)), evBypass(r))
	tile(&b, "False positives", pctf(r.Benign.FPRate), fmt.Sprintf("%d/%d benign requests blocked", r.Benign.Blocked, r.Benign.Total))
	tile(&b, "Inspection p50 / p99", us(r.Latency.P50)+" / "+us(r.Latency.P99), fmt.Sprintf("%s requests timed", comma(r.Latency.Samples)))
	p(`</section>`)

	p(`<section class="panel"><h2>Method</h2><p>The engine seeded %d base attacks across four classes, placed each one in %d request positions (query, form, JSON, header, cookie and six structural / parser-differential shapes), and — guided only by the WAF's own verdicts — kept every attack the WAF caught and applied %d evasion transformations to it, repeating for %d generations. Every request was also sent to a demo backend that echoes what it parsed, so a block only counts against an attack that actually reached an application parameter. No step was scripted; the search path was decided from live results.</p></section>`,
		len(seeds()), len(placements()), len(mutators())-1, r.Generations)

	// tuning loop history: what the engine found, what changed, what it found next
	if len(r.History) > 1 {
		p(`<section class="panel"><h2>Autonomous tuning loop</h2><p>Each row is a full campaign. The engine's findings from one run drove the change before the next; the runs below are real, re-executed from the repository's history.</p><table><thead><tr><th>Run</th><th class="num">Attacks</th><th class="num">Reached app</th><th class="num">Detection</th><th class="num">Bypasses</th><th class="num">False pos.</th><th>What happened</th></tr></thead><tbody>`)
		for _, h := range r.History {
			p(`<tr><td><b>%s</b><div class="ts">%s</div></td><td class="num">%s</td><td class="num">%s</td><td class="num">%s</td><td class="num">%d</td><td class="num">%s</td><td>%s`,
				html.EscapeString(h.Label), h.Time.Format("2006-01-02 15:04 UTC"), comma(h.Trials), comma(h.Landed),
				pctf(h.Detection), h.Bypasses, pctf(h.FPRate), html.EscapeString(h.Note))
			if len(h.Samples) > 0 {
				p(`<div class="mono" style="margin-top:4px">`)
				for _, s := range h.Samples {
					p(`%s<br>`, html.EscapeString(s))
				}
				p(`</div>`)
			}
			p(`</td></tr>`)
		}
		p(`</tbody></table></section>`)
	}

	// per-class detection chart
	p(`<section class="panel"><h2>Detection by attack class</h2>%s</section>`, classChart(r))

	// bypasses
	if len(r.Bypasses) == 0 {
		p(`<section class="panel ok"><h2>Confirmed bypasses</h2><p><b>None.</b> Every attack that reached the application was blocked, including all structural / parser-differential variants the search produced.</p></section>`)
	} else {
		p(`<section class="panel bad"><h2>Confirmed bypasses (%d)</h2><p>Each reached an application parameter and was not blocked.</p><table><thead><tr><th>Class</th><th>Placement</th><th>Mutator</th><th>Gen</th><th>Payload</th></tr></thead><tbody>`, len(r.Bypasses))
		for _, t := range r.Bypasses {
			p(`<tr><td>%s</td><td>%s%s</td><td>%s</td><td class="num">%d</td><td class="mono">%s</td></tr>`,
				t.Class, t.Placement, struct_(t.Structural), t.Mutator, t.Generation, html.EscapeString(t.Payload))
		}
		p(`</tbody></table></section>`)
	}

	// tuning
	if len(r.Tuning) > 0 {
		p(`<section class="panel"><h2>Operating point (auto-tuned)</h2><p>Detection and false positives measured at each paranoia level; the recommended point is the highest detection within the false-positive budget.</p>%s<table><thead><tr><th>Paranoia</th><th>Threshold</th><th class="num">Detection</th><th class="num">False positives</th><th></th></tr></thead><tbody>`, tuneChart(r))
		for _, tp := range r.Tuning {
			rec := ""
			if tp.Recommended {
				rec = `<span class="pill">recommended</span>`
			}
			p(`<tr%s><td class="num">%d</td><td class="num">%d</td><td class="num">%s</td><td class="num">%s</td><td>%s</td></tr>`,
				recClass(tp.Recommended), tp.Paranoia, tp.Threshold, pctf(tp.DetectionRate), pctf(tp.FPRate), rec)
		}
		p(`</tbody></table></section>`)
	}

	// evidence
	status := "FAILED"
	cls := "bad"
	if evidenceOK {
		status, cls = "VERIFIED", "ok"
	}
	p(`<section class="panel %s"><h2>Evidence integrity</h2><p>Every blocked attack and every bypass was written to an append-only SHA-256 hash chain. Re-verification: <b>%s</b> · %d records · head <span class="mono">%s</span>. Editing, deleting or reordering any record breaks the chain.</p></section>`,
		cls, status, evidenceRecords, html.EscapeString(shorten(evidenceHead)))

	// screenshots
	for _, s := range r.Shots {
		data, err := os.ReadFile(s.Path)
		if err != nil {
			continue
		}
		enc := base64.StdEncoding.EncodeToString(data)
		p(`<section class="panel shotp"><h2>%s</h2><p>%s</p><img class="shot" alt="%s" src="data:image/png;base64,%s"></section>`,
			html.EscapeString(s.Title), html.EscapeString(s.Caption), html.EscapeString(s.Title), enc)
	}

	p(`<footer>Sentinel WAF %s · autonomous evaluation engine · all tests run against a local demo application · %d ms</footer>`,
		html.EscapeString(wafVersion), r.DurationMS)
	p(`</body></html>`)
	return b.String()
}

func classChart(r *Report) string {
	classes := []Class{SQLi, XSS, CmdI, Traversal}
	var b strings.Builder
	w, rowH, lab := 600, 26, 92
	b.WriteString(fmt.Sprintf(`<svg viewBox="0 0 %d %d" class="chart" role="img" aria-label="Detection rate by class">`, w, rowH*len(classes)+10))
	for i, c := range classes {
		cs := r.ByClass[c]
		y := i*rowH + 8
		bw := float64(w-lab-130) * clampRate(cs.Rate)
		b.WriteString(fmt.Sprintf(`<text x="0" y="%d" class="cl">%s</text>`, y+13, c))
		b.WriteString(fmt.Sprintf(`<rect x="%d" y="%d" width="%d" height="12" rx="2" fill="var(--track)"/>`, lab, y+4, w-lab-130))
		b.WriteString(fmt.Sprintf(`<rect x="%d" y="%d" width="%.0f" height="12" rx="2" fill="var(--bar)"/>`, lab, y+4, bw))
		b.WriteString(fmt.Sprintf(`<text x="%d" y="%d" class="val">%s (%d/%d)</text>`, w-122, y+14, pctf(cs.Rate), cs.Blocked, cs.Landed))
	}
	b.WriteString(`</svg>`)
	return b.String()
}

func tuneChart(r *Report) string {
	var b strings.Builder
	w, h, n := 560, 150, len(r.Tuning)
	if n == 0 {
		return ""
	}
	gw := float64(w-40) / float64(n)
	b.WriteString(fmt.Sprintf(`<svg viewBox="0 0 %d %d" class="chart" role="img" aria-label="Detection and false positives per paranoia level">`, w, h))
	b.WriteString(fmt.Sprintf(`<line x1="34" y1="%d" x2="%d" y2="%d" stroke="var(--line)"/>`, h-24, w-6, h-24))
	for i, tp := range r.Tuning {
		x := 40 + float64(i)*gw
		db := clampRate(tp.DetectionRate) * float64(h-40)
		fb := clampRate(tp.FPRate) * float64(h-40)
		b.WriteString(fmt.Sprintf(`<rect x="%.0f" y="%.0f" width="%.0f" height="%.0f" rx="2" fill="var(--bar)"/>`, x, float64(h-24)-db, gw*0.32, db))
		b.WriteString(fmt.Sprintf(`<rect x="%.0f" y="%.0f" width="%.0f" height="%.0f" rx="2" fill="var(--crit)"/>`, x+gw*0.36, float64(h-24)-fb, gw*0.32, fb))
		lab := fmt.Sprintf("PL%d", tp.Paranoia)
		if tp.Recommended {
			lab += "★"
		}
		b.WriteString(fmt.Sprintf(`<text x="%.0f" y="%d" class="ax">%s</text>`, x+gw*0.3, h-10, lab))
	}
	b.WriteString(fmt.Sprintf(`<text x="0" y="12" class="ax">100%%</text><text x="0" y="%d" class="ax">0%%</text>`, h-28))
	b.WriteString(fmt.Sprintf(`<rect x="%d" y="2" width="9" height="9" fill="var(--bar)"/><text x="%d" y="10" class="ax">detection</text><rect x="%d" y="2" width="9" height="9" fill="var(--crit)"/><text x="%d" y="10" class="ax">false pos.</text>`, w-170, w-158, w-92, w-80))
	b.WriteString(`</svg>`)
	return b.String()
}

func tile(b *strings.Builder, label, value, sub string) {
	fmt.Fprintf(b, `<div class="tile"><div class="tl">%s</div><div class="tv">%s</div><div class="ts">%s</div></div>`,
		html.EscapeString(label), html.EscapeString(value), html.EscapeString(sub))
}

func headline(r *Report) string {
	if len(r.Bypasses) == 0 && r.Benign.FPRate == 0 {
		return "PASS · 0 bypasses · 0 false positives"
	}
	return fmt.Sprintf("%d bypass(es) · %s FP", len(r.Bypasses), pctf(r.Benign.FPRate))
}

func evBypass(r *Report) string {
	if len(r.Bypasses) == 0 {
		return "no evasion found by the search"
	}
	return "landed and not blocked"
}

func clampRate(f float64) float64 {
	if f < 0 {
		return 0
	}
	if f > 1 {
		return 1
	}
	return f
}
func boolClass(ok bool) string {
	if ok {
		return "ok"
	}
	return "bad"
}
func recClass(ok bool) string {
	if ok {
		return ` class="rec"`
	}
	return ""
}
func struct_(s bool) string {
	if s {
		return `<span class="pill">structural</span>`
	}
	return ""
}
func pctf(f float64) string { return fmt.Sprintf("%.1f%%", f*100) }
func us(ns int64) string {
	if ns >= 1_000_000 {
		return fmt.Sprintf("%.2f ms", float64(ns)/1e6)
	}
	return fmt.Sprintf("%.1f µs", float64(ns)/1000)
}
func comma(n int) string {
	s := itoa(n)
	if n < 1000 {
		return s
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}
func shorten(h string) string {
	if len(h) > 24 {
		return h[:24] + "…"
	}
	return h
}

const reportCSS = `
:root{--ink:#14161a;--muted:#5b616b;--line:#d7dade;--track:#e7e9ec;--bar:#2a78d6;--crit:#d03b3b;--ok:#0ca30c;--surf:#fbfcfd}
*{box-sizing:border-box}body{font:13px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;color:var(--ink);margin:0;background:#fff}
header{display:flex;justify-content:space-between;align-items:center;padding:22px 32px;border-bottom:3px solid var(--ink)}
h1{font-size:22px;margin:0}.sub{color:var(--muted);font-size:12.5px;margin-top:3px}
.stamp{font-weight:700;font-size:13px;padding:6px 12px;border-radius:5px}
.stamp.ok{background:#e5f4e5;color:var(--ok)}.stamp.bad{background:#f9e1e1;color:var(--crit)}
.tiles{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;padding:20px 32px}
.tile{border:1px solid var(--line);border-radius:7px;padding:12px 14px;background:var(--surf)}
.tl{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
.tv{font-size:23px;font-weight:650;margin:3px 0;font-variant-numeric:tabular-nums}
.ts{font-size:11.5px;color:var(--muted)}
.panel{margin:12px 32px;padding:14px 18px;border:1px solid var(--line);border-radius:7px;break-inside:avoid}
.panel.ok{border-left:4px solid var(--ok)}.panel.bad{border-left:4px solid var(--crit)}
h2{font-size:14px;margin:0 0 8px}p{margin:4px 0 10px}
table{width:100%;border-collapse:collapse;font-size:12px}th{text-align:left;color:var(--muted);text-transform:uppercase;font-size:10.5px;letter-spacing:.04em;border-bottom:1px solid var(--line);padding:5px 7px}
td{padding:5px 7px;border-bottom:1px solid var(--track);vertical-align:top}.num{text-align:right;font-variant-numeric:tabular-nums}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:11px;word-break:break-all}
tr.rec{background:#eef5fd}.pill{display:inline-block;font-size:10px;background:#eef1f5;border:1px solid var(--line);border-radius:3px;padding:0 5px;margin-left:4px;color:var(--muted)}
.chart{width:100%;max-width:620px}.chart .cl{font-size:12px;fill:var(--ink)}.chart .val{font-size:11px;fill:var(--muted)}.chart .ax{font-size:10px;fill:var(--muted)}
.shot{width:100%;border:1px solid var(--line);border-radius:6px;margin-top:6px}.shotp{break-before:page}
footer{color:var(--muted);font-size:11px;padding:18px 32px;border-top:1px solid var(--line);margin-top:14px}
@media print{.panel,.tile{break-inside:avoid}header{position:running(h)}}
`
