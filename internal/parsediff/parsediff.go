// Package parsediff reads a request body the way several different HTTP
// parsers would and reports where those readings disagree.
//
// Most WAF bypasses of the last few years (WAFFLED, ACSAC 2025; JSON-in-SQL,
// Team82 2022; HTTP parameter pollution, Ethiack 2025; CVE-2026-41508 in
// Coraza) do not hide the payload itself. They hide its *structure*: the WAF
// parses the body one way, the application framework parses it another way,
// and the payload sits in the part only the application reads.
//
// parsediff closes that gap in two steps:
//
//  1. Union inspection. Every field produced by ANY reading (strict RFC, Go's
//     own standard library, and the lenient behaviours other frameworks are
//     known to have) is returned, so the detectors see every value any
//     backend could see.
//  2. Consensus. Where readings disagree in a way that changes what a backend
//     receives (duplicate JSON keys with different values, two multipart
//     boundaries, parts after the closing delimiter, ...) an Ambiguity is
//     reported with a score, so a request whose meaning depends on which
//     parser reads it can be rejected even if no payload is recognised.
//
// The Go reading uses the real standard-library parsers (mime/multipart,
// encoding/json, net/url), so for a Go backend the WAF's view is the
// backend's view by construction.
package parsediff

import (
	"bytes"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Severity scores, CRS-compatible (5 = critical, blocks alone at the default threshold).
const (
	Critical = 5
	Warning  = 3
	Notice   = 2
)

// Field kinds.
const (
	KindForm      = "form"
	KindQuery     = "query"
	KindJSON      = "json"
	KindMultipart = "multipart"
	KindRaw       = "raw"
)

// Field is one value some reading of the body produced.
type Field struct {
	Kind        string
	Name        string // parameter / part name / JSON path
	Value       string
	Filename    string
	HasFilename bool
	Key         bool   // true: Value is a key/parameter name, not a value
	Reading     string // which reading produced it (first one wins on duplicates)
}

// Ambiguity is a point where parsers disagree.
type Ambiguity struct {
	Code   string `json:"code"`
	Score  int    `json:"score"`
	Detail string `json:"detail"`
}

// Result is the union of all readings plus the disagreements found.
type Result struct {
	Fields      []Field
	Ambiguities []Ambiguity
	Readings    []string // readings that produced output
}

const (
	maxFields = 512
	maxDepth  = 32
	maxPart   = 1 << 20
)

type acc struct {
	res      Result
	seen     map[string]bool
	ambSeen  map[string]bool
	readSeen map[string]bool
}

func newAcc() *acc {
	return &acc{seen: map[string]bool{}, ambSeen: map[string]bool{}, readSeen: map[string]bool{}}
}

func (a *acc) field(f Field) {
	if len(a.res.Fields) >= maxFields || (f.Value == "" && f.Filename == "") {
		return
	}
	k := f.Kind + "\x00" + f.Name + "\x00" + f.Value + "\x00" + f.Filename
	if f.Key {
		k = "k\x00" + k
	}
	if a.seen[k] {
		return
	}
	a.seen[k] = true
	a.res.Fields = append(a.res.Fields, f)
}

func (a *acc) amb(code string, score int, detail string) {
	if a.ambSeen[code] {
		return
	}
	a.ambSeen[code] = true
	a.res.Ambiguities = append(a.res.Ambiguities, Ambiguity{Code: code, Score: score, Detail: detail})
}

func (a *acc) reading(name string) {
	if !a.readSeen[name] {
		a.readSeen[name] = true
		a.res.Readings = append(a.res.Readings, name)
	}
}

// Score is the sum of ambiguity scores.
func (r Result) Score() int {
	s := 0
	for _, a := range r.Ambiguities {
		s += a.Score
	}
	return s
}

var safeCharsets = map[string]bool{"": true, "utf-8": true, "utf8": true, "us-ascii": true, "ascii": true, "iso-8859-1": true, "latin1": true}

var (
	reMediaType = regexp.MustCompile(`^\s*([A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+)`)
	reCharset   = regexp.MustCompile(`(?i)charset\s*=\s*"?([^";,\s]+)`)
)

// bodyKind maps a media type to the reading family.
func bodyKind(mt string) string {
	mt = strings.ToLower(strings.TrimSpace(mt))
	switch {
	case mt == "application/x-www-form-urlencoded":
		return KindForm
	case mt == "application/json" || strings.HasSuffix(mt, "+json"):
		return KindJSON
	case strings.HasPrefix(mt, "multipart/"):
		return KindMultipart
	case strings.Contains(mt, "xml"):
		return "xml"
	}
	return ""
}

// sniff guesses what a body is from its bytes.
func sniff(body []byte) string {
	t := bytes.TrimLeft(bytes.TrimPrefix(body, []byte("\xef\xbb\xbf")), " \t\r\n")
	switch {
	case len(t) == 0:
		return ""
	case t[0] == '{' || t[0] == '[':
		return KindJSON
	case bytes.HasPrefix(t, []byte("--")) && bytes.Contains(t, []byte("Content-Disposition")),
		bytes.HasPrefix(t, []byte("--")) && bytes.Contains(bytes.ToLower(t), []byte("content-disposition")):
		return KindMultipart
	case t[0] == '<':
		return "xml"
	case bytes.IndexByte(t, '=') > 0 && !bytes.ContainsAny(t, " \r\n<>{}"):
		return KindForm
	}
	return ""
}

// Body reads a request body under every reading that could apply and
// returns the union of fields and the disagreements. header is the request
// header (Content-Type may appear more than once).
func Body(header http.Header, body []byte) Result {
	a := newAcc()
	if len(body) == 0 {
		return a.res
	}
	cts := header.Values("Content-Type")
	if len(cts) > 1 {
		distinct := map[string]bool{}
		for _, c := range cts {
			distinct[strings.ToLower(strings.TrimSpace(c))] = true
		}
		if len(distinct) > 1 {
			a.amb("content-type-duplicate", Critical,
				"request carries "+itoa(len(cts))+" different Content-Type headers; servers disagree on which one wins")
		}
	}
	if len(cts) == 0 {
		cts = []string{""}
	}

	kinds := map[string]bool{}
	for _, ct := range cts {
		mt, params, err := mime.ParseMediaType(ct)
		if err != nil && ct != "" {
			// Lenient reading of a broken header: first token as media type.
			if m := reMediaType.FindStringSubmatch(ct); m != nil {
				mt = strings.ToLower(m[1])
			}
			a.amb("content-type-malformed", Warning, "Content-Type does not parse strictly ("+err.Error()+"); lenient parsers still accept it")
		}
		cs := strings.ToLower(params["charset"])
		if m := reCharset.FindStringSubmatch(ct); m != nil && cs == "" {
			cs = strings.ToLower(m[1])
		}
		if !safeCharsets[cs] {
			a.amb("body-charset", Critical, "body declared as charset "+cs+"; the backend may decode bytes the WAF cannot read (e.g. ibm037, utf-16, utf-7)")
		}
		k := bodyKind(mt)
		if k == KindMultipart {
			multipartReadings(a, ct, body)
		}
		if k != "" {
			kinds[k] = true
		}
	}

	sn := sniff(body)
	declared := ""
	for k := range kinds {
		declared = k
	}
	if sn != "" && !kinds[sn] && declared != "" && declared != "xml" {
		a.amb("content-type-mismatch", Warning,
			"body looks like "+sn+" but is declared "+declared+"; frameworks that sniff or force-parse read a different structure")
	}
	if sn != "" && !kinds[sn] {
		kinds[sn] = true // read it as what it looks like too (union)
	}

	for k := range kinds {
		switch k {
		case KindForm:
			form(a, string(body), KindForm)
		case KindJSON:
			jsonReadings(a, body)
		case KindMultipart:
			if !hasMultipartCT(cts) {
				multipartReadings(a, "", body) // sniffed only: recover the boundary from the body
			}
		}
	}
	if !utf8.Valid(body) && !kinds[KindMultipart] {
		a.amb("body-invalid-utf8", Warning, "body is not valid UTF-8; parsers differ in how they repair it")
	}
	return a.res
}

func hasMultipartCT(cts []string) bool {
	for _, c := range cts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(c)), "multipart/") {
			return true
		}
	}
	return false
}

// Query reads a URL query string (same readings as a urlencoded body).
func Query(raw string) Result {
	a := newAcc()
	form(a, raw, KindQuery)
	return a.res
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
