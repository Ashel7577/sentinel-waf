// Command attacklab runs a live attack campaign and produces an evidence pack.
//
// It starts three real HTTP servers on localhost:
//
//   - a Go web application (the "victim") that parses requests with the
//     standard library exactly like a typical Go handler and reports every
//     value it received, so "the payload reached the application" is measured,
//     not assumed;
//   - Sentinel WAF in front of it (evidence capture on);
//   - OWASP Coraza + Core Rule Set v4 in front of it (the open-source baseline).
//
// Every attack in the campaign is sent three times: straight to the app (proof
// of impact), through Coraza+CRS and through Sentinel. The output directory
// gets the hash-chained evidence file, the analyst's incident report
// (Markdown + HTML), a results table and the raw outcomes as JSON.
//
//	go run ./attacklab -out ../../lab-out
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"

	"github.com/Ashel7577/sentinel-waf/internal/analyst"
	"github.com/Ashel7577/sentinel-waf/internal/evidence"
	"github.com/Ashel7577/sentinel-waf/internal/server"
	"github.com/Ashel7577/sentinel-waf/internal/waf"
)

const sqli = "1' UNION SELECT username,password FROM users--"

// marker is what the oracle looks for in the values the app received.
const marker = "UNION SELECT"

type attack struct {
	Name   string
	Class  string // "classic" or the bypass class
	Method string
	Path   string
	Header [][2]string // ordered; duplicates allowed
	Body   []byte
	Marker string
	Note   string
}

func h(kv ...string) [][2]string {
	var out [][2]string
	for i := 0; i+1 < len(kv); i += 2 {
		out = append(out, [2]string{kv[i], kv[i+1]})
	}
	return out
}

func qp(s string) string { // quoted-printable encode every byte
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "=%02X", s[i])
	}
	return b.String()
}

func campaign() []attack {
	var mp bytes.Buffer
	mw := multipart.NewWriter(&mp)
	_ = mw.WriteField("comment", sqli)
	_ = mw.Close()

	lf := "--XB\nContent-Disposition: form-data; name=\"comment\"\n\n" + sqli + "\n--XB--\n"
	qpBody := "--XB\r\nContent-Disposition: form-data; name=\"comment\"\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n" + qp(sqli) + "\r\n--XB--\r\n"
	afterClose := "--XB\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nhello\r\n--XB--\r\n--XB\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\n" + sqli + "\r\n--XB--\r\n"
	twoBound := "--BBB\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\n" + sqli + "\r\n--BBB--\r\n"
	fnStar := "--XB\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"notes.txt\"; filename*=UTF-8''..%2F..%2F..%2Fetc%2Fpasswd\r\nContent-Type: text/plain\r\n\r\nhello\r\n--XB--\r\n"

	return []attack{
		// Classic payloads: both WAFs should block; shows the baseline works.
		{Name: "SQLi in query string", Class: "classic", Method: "GET", Path: "/search?q=" + url.QueryEscape(sqli), Marker: marker},
		{Name: "XSS in form field", Class: "classic", Method: "POST", Path: "/form", Header: h("Content-Type", "application/x-www-form-urlencoded"),
			Body: []byte("comment=" + url.QueryEscape(`<img src=x onerror=alert(document.cookie)>`)), Marker: "onerror"},
		{Name: "Command injection in JSON", Class: "classic", Method: "POST", Path: "/api/json", Header: h("Content-Type", "application/json"),
			Body: []byte(`{"host":"127.0.0.1; cat /etc/passwd"}`), Marker: "cat /etc/passwd"},
		{Name: "Path traversal in query", Class: "classic", Method: "GET", Path: "/search?q=" + url.QueryEscape("../../../../etc/passwd"), Marker: "etc/passwd"},
		{Name: "SQLi in standard multipart", Class: "classic", Method: "POST", Path: "/form", Header: h("Content-Type", mw.FormDataContentType()), Body: mp.Bytes(), Marker: marker},

		// Parser differentials: the payload is unchanged, the structure is not.
		{Name: "JSON body sent as text/plain", Class: "content-type confusion", Method: "POST", Path: "/api/json",
			Header: h("Content-Type", "text/plain"), Body: []byte(`{"q":"` + sqli + `"}`), Marker: marker,
			Note: "Go handlers commonly json-decode r.Body without checking Content-Type"},
		{Name: "Duplicate JSON key (last wins)", Class: "JSON duplicate key", Method: "POST", Path: "/api/json",
			Header: h("Content-Type", "application/json"), Body: []byte(`{"q":"` + sqli + `","q":"hello"}`), Marker: marker,
			Note: "payload in the first copy: first-wins parsers see it, Go keeps the last"},
		{Name: "Duplicate JSON key (payload last)", Class: "JSON duplicate key", Method: "POST", Path: "/api/json",
			Header: h("Content-Type", "application/json"), Body: []byte(`{"q":"hello","q":"` + sqli + `"}`), Marker: marker},
		{Name: "Case-variant JSON key into Go struct", Class: "JSON case-insensitive key", Method: "POST", Path: "/api/json",
			Header: h("Content-Type", "application/json"), Body: []byte(`{"role":"user","ROLE":"` + sqli + `"}`), Marker: marker,
			Note: "encoding/json maps ROLE onto the Role struct field"},
		{Name: "JSON with comments", Class: "non-standard JSON", Method: "POST", Path: "/api/json",
			Header: h("Content-Type", "application/json"), Body: []byte(`{"q":"hi", /* x */ "z":"` + sqli + `",}`), Marker: marker,
			Note: "only relaxed (JSON5-style) backends accept this"},
		{Name: "Multipart with LF-only line endings", Class: "multipart line endings", Method: "POST", Path: "/form",
			Header: h("Content-Type", "multipart/form-data; boundary=XB"), Body: []byte(lf), Marker: marker},
		{Name: "Multipart quoted-printable part", Class: "multipart transfer encoding", Method: "POST", Path: "/form",
			Header: h("Content-Type", "multipart/form-data; boundary=XB"), Body: []byte(qpBody), Marker: marker,
			Note: "Go's mime/multipart decodes quoted-printable parts before the handler sees them"},
		{Name: "Multipart part after closing delimiter", Class: "multipart epilogue", Method: "POST", Path: "/form",
			Header: h("Content-Type", "multipart/form-data; boundary=XB"), Body: []byte(afterClose), Marker: marker},
		{Name: "Multipart with two boundaries", Class: "multipart boundary", Method: "POST", Path: "/form",
			Header: h("Content-Type", "multipart/form-data; boundary=AAA; boundary=BBB"), Body: []byte(twoBound), Marker: marker},
		{Name: "Traversal in filename*", Class: "multipart filename*", Method: "POST", Path: "/form",
			Header: h("Content-Type", "multipart/form-data; boundary=XB"), Body: []byte(fnStar), Marker: "etc/passwd"},
		{Name: "Two Content-Type headers", Class: "content-type duplicate", Method: "POST", Path: "/api/json",
			Header: h("Content-Type", "application/x-www-form-urlencoded", "Content-Type", "application/json"),
			Body:   []byte(`{"q":"` + sqli + `"}`), Marker: marker},
		{Name: "Parameter pollution split payload", Class: "HTTP parameter pollution", Method: "GET",
			Path: "/search?q=1'/*&q=*/UNION/*&q=*/SELECT+username,password+FROM+users--", Marker: "UNION/*,*/SELECT",
			Note: "ASP.NET joins duplicates with ','; a Go app reading q[0] does not"},
	}
}

// victim is a typical Go application. It reports every value it received.
func victim() http.Handler {
	type input struct {
		Role string
		Q    string
		Host string
	}
	mux := http.NewServeMux()
	report := func(w http.ResponseWriter, all []string) {
		vals := []string{}
		for _, v := range all {
			if v != "" {
				vals = append(vals, v)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"received": vals})
	}
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		report(w, r.URL.Query()["q"])
	})
	mux.HandleFunc("/form", func(w http.ResponseWriter, r *http.Request) {
		var vals []string
		_ = r.ParseMultipartForm(8 << 20) // falls back to ParseForm for urlencoded
		for _, vs := range r.Form {
			vals = append(vals, vs...)
		}
		if r.MultipartForm != nil {
			for _, fhs := range r.MultipartForm.File {
				for _, fh := range fhs {
					vals = append(vals, "file:"+fh.Filename)
				}
			}
		}
		report(w, vals)
	})
	mux.HandleFunc("/api/json", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var vals []string
		var m map[string]any
		if json.Unmarshal(body, &m) == nil {
			for _, v := range m {
				vals = append(vals, fmt.Sprint(v))
			}
		}
		var in input
		if json.Unmarshal(body, &in) == nil {
			vals = append(vals, in.Role, in.Q, in.Host)
		}
		report(w, vals)
	})
	return mux
}

type outcome struct {
	Attack       string `json:"attack"`
	Class        string `json:"class"`
	Note         string `json:"note,omitempty"`
	Delivered    bool   `json:"payload_reached_app"`
	AppReceived  string `json:"app_received"`
	CorazaStatus int    `json:"coraza_status"`
	SentStatus   int    `json:"sentinel_status"`
	RequestID    string `json:"sentinel_request_id"`
	Evidence     string `json:"evidence_hash,omitempty"`
}

func send(base string, a attack) (int, string, http.Header) {
	req, err := http.NewRequest(a.Method, base+a.Path, bytes.NewReader(a.Body))
	if err != nil {
		return 0, err.Error(), nil
	}
	req.Header.Set("User-Agent", "sentinel-attacklab/1.0")
	for _, kv := range a.Header {
		req.Header.Add(kv[0], kv[1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err.Error(), nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, string(b), resp.Header
}

func main() {
	out := flag.String("out", "lab-out", "output directory for the evidence pack")
	pl := flag.Int("paranoia", 1, "paranoia level for both WAFs")
	flag.Parse()
	must(os.MkdirAll(*out, 0o755))
	evPath := filepath.Join(*out, "evidence.jsonl")
	_ = os.Remove(evPath)

	app := httptest.NewServer(victim())
	defer app.Close()
	appURL, _ := url.Parse(app.URL)

	vault, err := evidence.Open(evPath)
	must(err)
	engine := waf.NewEngine(waf.Config{Paranoia: *pl}, waf.DefaultRules())
	sent := server.New(server.Options{Upstream: appURL, Evidence: vault, EvidencePath: evPath,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}, engine)
	sentSrv := httptest.NewServer(sent)
	defer sentSrv.Close()

	cw, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives("Include @coraza.conf-recommended").
		WithDirectives("Include @crs-setup.conf.example").
		WithDirectives(fmt.Sprintf(`SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d"`, *pl)).
		WithDirectives("Include @owasp_crs/*.conf").
		WithDirectives("SecRuleEngine On").
		WithDirectives("SecRequestBodyAccess On"))
	must(err)
	corSrv := httptest.NewServer(txhttp.WrapHandler(cw, httputil.NewSingleHostReverseProxy(appURL)))
	defer corSrv.Close()

	otherName := fmt.Sprintf("Coraza v3.8 + OWASP CRS v4.25 (PL%d)", *pl)
	var results []outcome
	lab := map[string]*analyst.LabOutcome{}
	start := time.Now()
	for _, a := range campaign() {
		_, appBody, _ := send(app.URL, a)
		var got struct{ Received []string }
		_ = json.Unmarshal([]byte(appBody), &got)
		delivered := false
		for _, v := range got.Received {
			if strings.Contains(v, a.Marker) || strings.Contains(strings.Join(got.Received, ","), a.Marker) {
				delivered = true
			}
		}
		cs, _, _ := send(corSrv.URL, a)
		ss, _, sh := send(sentSrv.URL, a)
		o := outcome{Attack: a.Name, Class: a.Class, Note: a.Note, Delivered: delivered, AppReceived: clip(strings.Join(got.Received, " | "), 160),
			CorazaStatus: cs, SentStatus: ss, RequestID: sh.Get("X-Request-ID")}
		results = append(results, o)
		proof := "the application's parameters contained the payload: `" + clip(strings.Join(got.Received, " | "), 120) + "`"
		if !delivered {
			proof = "the Go application did not receive the payload in a parameter (this structure targets other frameworks): `" + clip(strings.Join(got.Received, " | "), 80) + "`"
		}
		lab[o.RequestID] = &analyst.LabOutcome{Attack: a.Name, Class: a.Class, BackendProof: proof, PayloadInApp: delivered,
			OtherWAF: otherName, OtherVerdict: verdict(cs), SentinelHTTP: ss}
	}
	vault.Close()
	took := time.Since(start)

	recs, err := evidence.ReadFile(evPath)
	must(err)
	chain := evidence.Verify(recs)
	for i := range results {
		for _, r := range recs {
			if r.RequestID == results[i].RequestID {
				results[i].Evidence = r.Hash
			}
		}
	}
	md := analyst.Markdown(analyst.Analyse(recs, lab), chain, "Sentinel WAF attack campaign: incident report", "")
	must(os.WriteFile(filepath.Join(*out, "report.md"), []byte(md), 0o644))
	must(os.WriteFile(filepath.Join(*out, "report.html"), []byte(analyst.HTML(md)), 0o644))
	j, _ := json.MarshalIndent(map[string]any{"generated": time.Now().UTC(), "paranoia": *pl, "comparison": otherName,
		"evidence_chain": chain, "results": results}, "", "  ")
	must(os.WriteFile(filepath.Join(*out, "results.json"), j, 0o644))

	// Results table (also printed).
	var b strings.Builder
	fmt.Fprintf(&b, "## Attack campaign: Sentinel vs %s\n\n", otherName)
	b.WriteString("Each attack was sent to an unprotected Go application (to prove whether the payload reaches it), then through each WAF. 403/400 = the WAF stopped the request (the application itself always answers 200).\n\n")
	b.WriteString("| Attack | Class | Payload reached Go app | Coraza + CRS | Sentinel |\n|---|---|---|---|---|\n")
	deliv, corMiss, sentMiss, corMissDeliv, sentMissDeliv := 0, 0, 0, 0, 0
	for _, r := range results {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", r.Attack, r.Class, yn(r.Delivered), verdict(r.CorazaStatus), verdict(r.SentStatus))
		if r.Delivered {
			deliv++
		}
		if !stopped(r.CorazaStatus) {
			corMiss++
			if r.Delivered {
				corMissDeliv++
			}
		}
		if !stopped(r.SentStatus) {
			sentMiss++
			if r.Delivered {
				sentMissDeliv++
			}
		}
	}
	n := len(results)
	fmt.Fprintf(&b, "\n**%d attacks** · payload reached the unprotected Go app in %d · Coraza+CRS let %d through (%d of them live against the Go app) · Sentinel let %d through (%d live).\n",
		n, deliv, corMiss, corMissDeliv, sentMiss, sentMissDeliv)
	if chain.OK {
		fmt.Fprintf(&b, "\nEvidence: %d hash-chained records, chain **verified**, head `%s`. Campaign ran in %s.\n", chain.Records, chain.HeadHash, took.Round(time.Millisecond))
	} else {
		fmt.Fprintf(&b, "\nEvidence chain FAILED verification at record %d: %s\n", chain.BadSeq, chain.Problem)
	}
	must(os.WriteFile(filepath.Join(*out, "results.md"), []byte(b.String()), 0o644))
	fmt.Print(b.String())
	fmt.Printf("\nevidence pack: %s (evidence.jsonl, report.md, report.html, results.json, results.md)\n", *out)
}

func verdict(code int) string {
	switch {
	case code == 403:
		return "blocked (403)"
	case code == 400:
		return "rejected (400)" // the victim app always answers 200, so a 400 is the WAF refusing the body
	case code == 0:
		return "error"
	}
	return fmt.Sprintf("allowed (%d)", code)
}

func stopped(code int) bool { return code == 403 || code == 400 }

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "attacklab:", err)
		os.Exit(1)
	}
}
