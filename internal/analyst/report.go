package analyst

import (
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"github.com/Ashel7577/sentinel-waf/internal/evidence"
)

// LabOutcome is extra proof the attack lab attaches to an incident: what the
// unprotected backend did with the same request, and how another WAF judged it.
type LabOutcome struct {
	Attack       string // attack name in the campaign
	Class        string // bypass class / technique label
	BackendProof string // what the backend received when hit directly (no WAF)
	PayloadInApp bool   // the payload reached an application parameter
	OtherWAF     string // e.g. "Coraza + OWASP CRS v4.25 (PL1)"
	OtherVerdict string // "allowed" / "blocked (403)"
	SentinelHTTP int
}

// Incident is one analysed evidence record.
type Incident struct {
	Rec        *evidence.Record
	Techniques []Technique
	Lab        *LabOutcome
}

// Analyse groups each record with the techniques its findings point to.
func Analyse(recs []*evidence.Record, lab map[string]*LabOutcome) []Incident {
	var out []Incident
	for _, r := range recs {
		seen := map[string]bool{}
		inc := Incident{Rec: r}
		if lab != nil {
			inc.Lab = lab[r.RequestID]
		}
		for _, f := range sortedFindings(r.Findings) {
			if !seen[f.Category] {
				seen[f.Category] = true
				inc.Techniques = append(inc.Techniques, TechniqueFor(f.Category))
			}
		}
		out = append(out, inc)
	}
	return out
}

func sortedFindings(fs []evidence.Finding) []evidence.Finding {
	c := append([]evidence.Finding(nil), fs...)
	sort.SliceStable(c, func(i, j int) bool { return c[i].Score > c[j].Score })
	return c
}

// Summary line used by the dashboard and the LLM prompt.
func (in Incident) Summary() string {
	names := make([]string, 0, len(in.Techniques))
	for _, t := range in.Techniques {
		names = append(names, t.Name)
	}
	return fmt.Sprintf("#%d %s %s from %s: %s (score %d/%d, %s)", in.Rec.Seq, in.Rec.Method, clipS(in.Rec.URI, 60),
		in.Rec.ClientIP, strings.Join(names, " + "), in.Rec.Score, in.Rec.Threshold, in.Rec.Action)
}

// Markdown renders the full incident report.
func Markdown(incs []Incident, chain evidence.Report, title, narrative string) string {
	var b strings.Builder
	if title == "" {
		title = "Sentinel WAF incident report"
	}
	fmt.Fprintf(&b, "# %s\n\n", title)
	fmt.Fprintf(&b, "Generated %s by Sentinel's built-in analyst. Every statement below is taken from the evidence record or the technique knowledge base; nothing is inferred beyond it.\n\n", time.Now().UTC().Format(time.RFC1123))

	blocked, flagged := 0, 0
	tech := map[string]int{}
	for _, in := range incs {
		if in.Rec.Action == "blocked" {
			blocked++
		} else {
			flagged++
		}
		for _, t := range in.Techniques {
			tech[t.Name]++
		}
	}
	b.WriteString("## Summary\n\n")
	fmt.Fprintf(&b, "- **Incidents:** %d (%d blocked, %d flagged)\n", len(incs), blocked, flagged)
	if chain.OK {
		fmt.Fprintf(&b, "- **Evidence integrity:** VERIFIED. %d records, hash chain intact, head hash `%s`\n", chain.Records, chain.HeadHash)
	} else {
		fmt.Fprintf(&b, "- **Evidence integrity:** FAILED at record %d: %s\n", chain.BadSeq, chain.Problem)
	}
	if lab := labStats(incs); lab != "" {
		b.WriteString(lab)
	}
	if narrative != "" {
		b.WriteString("\n### Analyst narrative\n\n" + narrative + "\n")
	}
	b.WriteString("\n| Technique | Incidents |\n|---|---|\n")
	names := make([]string, 0, len(tech))
	for n := range tech {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		return tech[names[i]] > tech[names[j]] || tech[names[i]] == tech[names[j]] && names[i] < names[j]
	})
	for _, n := range names {
		fmt.Fprintf(&b, "| %s | %d |\n", n, tech[n])
	}

	if hasLab(incs) {
		b.WriteString("\n## Attack campaign results\n\n| # | Attack | Class | Payload reached app without WAF | Coraza + CRS | Sentinel |\n|---|---|---|---|---|---|\n")
		for _, in := range incs {
			if in.Lab == nil {
				continue
			}
			fmt.Fprintf(&b, "| %d | %s | %s | %s | %s | %s |\n", in.Rec.Seq, md(in.Lab.Attack), md(in.Lab.Class),
				yesno(in.Lab.PayloadInApp), md(in.Lab.OtherVerdict), in.Rec.Action)
		}
	}

	b.WriteString("\n## Incidents\n")
	for _, in := range incs {
		r := in.Rec
		fmt.Fprintf(&b, "\n### Incident %d: %s\n\n", r.Seq, md(techNames(in.Techniques)))
		fmt.Fprintf(&b, "| | |\n|---|---|\n| Time (UTC) | %s |\n| Request ID | `%s` |\n| Client | %s |\n| Request | `%s %s` |\n| Verdict | **%s** (anomaly score %d, threshold %d) |\n",
			r.Time.Format(time.RFC3339), r.RequestID, r.ClientIP, r.Method, md(clipS(r.URI, 120)), strings.ToUpper(r.Action), r.Score, r.Threshold)
		if in.Lab != nil {
			fmt.Fprintf(&b, "| Campaign attack | %s (%s) |\n", md(in.Lab.Attack), md(in.Lab.Class))
		}

		for _, t := range in.Techniques {
			fmt.Fprintf(&b, "\n**%s**", t.Name)
			if ids := techIDs(t); ids != "" {
				fmt.Fprintf(&b, " (%s)", ids)
			}
			fmt.Fprintf(&b, "\n\n- *How it works:* %s\n- *Impact if it had reached the app:* %s\n- *Fix in the application:* %s\n", t.HowItWorks, t.Impact, t.Fix)
			for _, ref := range t.Refs {
				fmt.Fprintf(&b, "- Reference: %s\n", ref)
			}
		}

		b.WriteString("\n**How Sentinel detected and stopped it**\n\n| Rule | Category | Where | Score | Detail |\n|---|---|---|---|---|\n")
		for _, f := range sortedFindings(r.Findings) {
			where := f.Location
			if f.Name != "" {
				where += " `" + md(clipS(f.Name, 40)) + "`"
			}
			detail := f.Message
			if f.Category == "parser-differential" {
				detail = ParseDiffWhy(f.Name)
			} else if f.Sample != "" {
				detail += " — value `" + md(clipS(f.Sample, 80)) + "`"
			}
			fmt.Fprintf(&b, "| %d | %s | %s | %d | %s |\n", f.RuleID, f.Category, where, f.Score, md(detail))
		}
		fmt.Fprintf(&b, "\nThe findings add up to %d, at or above the block threshold of %d, so the request was %s before it reached the application.\n",
			r.Score, r.Threshold, verdictWord(r.Action))

		if in.Lab != nil {
			b.WriteString("\n**Proof of impact and comparison**\n\n")
			fmt.Fprintf(&b, "- Sent straight to the application (no WAF): %s\n", md(in.Lab.BackendProof))
			fmt.Fprintf(&b, "- Same request through %s: **%s**\n", md(in.Lab.OtherWAF), md(in.Lab.OtherVerdict))
			fmt.Fprintf(&b, "- Through Sentinel: **HTTP %d (%s)**\n", in.Lab.SentinelHTTP, r.Action)
		}

		b.WriteString("\n**Evidence**\n\n")
		fmt.Fprintf(&b, "- Record #%d hash `%s` (previous `%s`)\n- Raw request SHA-256 `%s`, body SHA-256 `%s` (%d bytes%s)\n",
			r.Seq, r.Hash, r.PrevHash, r.RawSHA256, r.BodySHA256, r.BodyLen, truncNote(r.BodyTrunc))
		raw := string(r.Raw())
		if len(raw) > 4000 {
			raw = raw[:4000] + "\n... (truncated in report; full body in the evidence file)"
		}
		fmt.Fprintf(&b, "\n```http\n%s\n```\n", strings.ReplaceAll(raw, "```", "'''"))
		fmt.Fprintf(&b, "\nReproduce:\n\n```bash\n%s\n```\n", curl(r))
	}
	b.WriteString("\n---\nVerify this evidence independently: `sentinel-report verify -evidence <file>` re-computes every SHA-256 link of the chain.\n")
	return b.String()
}

// HTML wraps the Markdown report in a minimal standalone page (no external
// assets, prints cleanly).
func HTML(markdown string) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sentinel incident report</title><style>
body{font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif;max-width:980px;margin:32px auto;padding:0 16px;color:#1d2430;background:#fff}
h1{font-size:26px;border-bottom:2px solid #1d2430;padding-bottom:8px}h2{margin-top:36px;font-size:20px}h3{margin-top:30px;font-size:17px;border-top:1px solid #dde2ea;padding-top:18px}
table{border-collapse:collapse;width:100%;margin:10px 0;font-size:13.5px}td,th{border:1px solid #dde2ea;padding:6px 8px;text-align:left;vertical-align:top}th{background:#f4f6f9}
code{background:#f4f6f9;padding:1px 4px;border-radius:3px;font-size:12.5px;word-break:break-all}pre{background:#0f141c;color:#e6edf3;padding:12px;border-radius:6px;overflow:auto;font-size:12.5px;white-space:pre-wrap;word-break:break-all}
strong{color:#0f141c}.ok{color:#137333}.bad{color:#b3261e}
@media (prefers-color-scheme:dark){body{background:#0f141c;color:#d6dde6}th{background:#1a212c}td,th{border-color:#2a3340}code{background:#1a212c}strong{color:#fff}h1{border-color:#d6dde6}}
</style></head><body>`)
	b.WriteString(mdToHTML(markdown))
	b.WriteString("</body></html>")
	return b.String()
}

// mdToHTML converts the small Markdown subset Markdown() emits.
func mdToHTML(md string) string {
	var b strings.Builder
	lines := strings.Split(md, "\n")
	inCode, inTable, inList := false, false, false
	closeBlocks := func() {
		if inTable {
			b.WriteString("</table>")
			inTable = false
		}
		if inList {
			b.WriteString("</ul>")
			inList = false
		}
	}
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "```"):
			closeBlocks()
			if inCode {
				b.WriteString("</pre>")
			} else {
				b.WriteString("<pre>")
			}
			inCode = !inCode
		case inCode:
			b.WriteString(html.EscapeString(l) + "\n")
		case strings.HasPrefix(l, "|"):
			if inList {
				b.WriteString("</ul>")
				inList = false
			}
			if strings.HasPrefix(l, "|---") {
				continue
			}
			cells := strings.Split(strings.Trim(l, "|"), " | ")
			if !inTable {
				b.WriteString("<table>")
				inTable = true
			}
			b.WriteString("<tr>")
			for _, c := range cells {
				b.WriteString("<td>" + inline(strings.TrimSpace(c)) + "</td>")
			}
			b.WriteString("</tr>")
		case strings.HasPrefix(l, "- "):
			if inTable {
				b.WriteString("</table>")
				inTable = false
			}
			if !inList {
				b.WriteString("<ul>")
				inList = true
			}
			b.WriteString("<li>" + inline(l[2:]) + "</li>")
		default:
			closeBlocks()
			switch {
			case strings.HasPrefix(l, "### "):
				b.WriteString("<h3>" + inline(l[4:]) + "</h3>")
			case strings.HasPrefix(l, "## "):
				b.WriteString("<h2>" + inline(l[3:]) + "</h2>")
			case strings.HasPrefix(l, "# "):
				b.WriteString("<h1>" + inline(l[2:]) + "</h1>")
			case l == "---":
				b.WriteString("<hr>")
			case strings.TrimSpace(l) != "":
				b.WriteString("<p>" + inline(l) + "</p>")
			}
		}
	}
	closeBlocks()
	return b.String()
}

func inline(s string) string {
	s = strings.ReplaceAll(s, `\|`, "|")
	parts := strings.Split(s, "`")
	var b strings.Builder
	for i, p := range parts {
		if i%2 == 1 && i < len(parts)-1 {
			b.WriteString("<code>" + html.EscapeString(p) + "</code>")
			continue
		}
		if i%2 == 1 {
			b.WriteString("`")
		}
		e := html.EscapeString(p)
		e = replacePairs(e, "**", "<strong>", "</strong>")
		e = replacePairs(e, "*", "<em>", "</em>")
		e = strings.ReplaceAll(e, "VERIFIED", `<span class="ok">VERIFIED</span>`)
		e = strings.ReplaceAll(e, "FAILED", `<span class="bad">FAILED</span>`)
		b.WriteString(e)
	}
	return b.String()
}

// replacePairs turns tok...tok pairs into open...close; an unpaired last
// token is kept literally.
func replacePairs(s, tok, open, close string) string {
	n := strings.Count(s, tok)
	if n < 2 {
		return s
	}
	parts := strings.Split(s, tok)
	var b strings.Builder
	for i, p := range parts {
		if i > 0 {
			switch {
			case i > n-n%2:
				b.WriteString(tok)
			case i%2 == 1:
				b.WriteString(open)
			default:
				b.WriteString(close)
			}
		}
		b.WriteString(p)
	}
	return b.String()
}

func labStats(incs []Incident) string {
	n, reached, otherMissed := 0, 0, 0
	for _, in := range incs {
		if in.Lab == nil {
			continue
		}
		n++
		if in.Lab.PayloadInApp {
			reached++
		}
		if strings.HasPrefix(in.Lab.OtherVerdict, "allowed") {
			otherMissed++
		}
	}
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("- **Attack campaign:** %d attacks; %d delivered their payload to the unprotected application; %d passed %s; Sentinel stopped all %d recorded here\n",
		n, reached, otherMissed, otherWAFName(incs), n)
}

func otherWAFName(incs []Incident) string {
	for _, in := range incs {
		if in.Lab != nil && in.Lab.OtherWAF != "" {
			return in.Lab.OtherWAF
		}
	}
	return "the comparison WAF"
}

func hasLab(incs []Incident) bool {
	for _, in := range incs {
		if in.Lab != nil {
			return true
		}
	}
	return false
}

func techNames(ts []Technique) string {
	n := make([]string, 0, len(ts))
	for _, t := range ts {
		n = append(n, t.Name)
	}
	if len(n) == 0 {
		return "Suspicious request"
	}
	return strings.Join(n, " + ")
}

func techIDs(t Technique) string {
	var ids []string
	for _, x := range []string{t.CWE, t.CAPEC, t.ATTACK} {
		if x != "" {
			ids = append(ids, x)
		}
	}
	return strings.Join(ids, " · ")
}

func curl(r *evidence.Record) string {
	var b strings.Builder
	fmt.Fprintf(&b, "curl -i -X %s 'http://TARGET%s'", r.Method, strings.ReplaceAll(r.URI, "'", `'\''`))
	keys := make([]string, 0, len(r.Headers))
	for k := range r.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		lk := strings.ToLower(k)
		if lk == "content-length" || lk == "user-agent" || lk == "accept-encoding" {
			continue
		}
		for _, v := range r.Headers[k] {
			fmt.Fprintf(&b, " \\\n  -H '%s: %s'", k, strings.ReplaceAll(v, "'", `'\''`))
		}
	}
	if r.BodyLen > 0 {
		fmt.Fprintf(&b, " \\\n  --data-binary \"$(printf '%%s' '%s' | base64 -d)\"", r.BodyB64)
	}
	return b.String()
}

func md(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "|", `\|`), "\n", " ") }

func clipS(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func verdictWord(a string) string {
	if a == "blocked" {
		return "rejected with HTTP 403"
	}
	return "flagged (monitor mode)"
}

func truncNote(t bool) string {
	if t {
		return ", body truncated to 64 KiB in the record"
	}
	return ""
}
