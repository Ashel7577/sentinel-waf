package waf

import (
	"bytes"
	"encoding/xml"
	"mime"
	"net/http"
	"strings"

	"github.com/Ashel7577/sentinel-waf/internal/parsediff"
)

// Input is one attacker-controllable value pulled out of a request.
type Input struct {
	Location string // see the loc* constants
	Name     string // parameter / header / JSON path
	Value    string
	score    int // parser-differential inputs only: the ambiguity score
}

// Input locations. They decide which analysers run on a value.
const (
	locPath      = "path"         // whole path: traversal + rules
	locSegment   = "path-segment" // one decoded path segment: full analysis
	locQuery     = "query"
	locBody      = "body"
	locJSON      = "json"
	locXML       = "xml"
	locCookie    = "cookie"
	locHeader    = "header"     // non-standard header: full analysis
	locStdHdr    = "header-std" // well-known header: rules only
	locKey       = "key"        // parameter / JSON key names
	locFilename  = "filename"   // multipart upload filename (raw, not basename'd)
	locFile      = "file"       // uploaded file content: rules only
	locBodyRaw   = "body-raw"   // entire raw body: rules only (XXE, etc.)
	locParseDiff = "parse-diff" // parsers disagree on this request (see internal/parsediff)
)

const (
	maxInputs = 512
	maxPart   = 1 << 20 // multipart part read cap (the body itself is already size-limited)
	maxDepth  = 32
)

// Well-known headers whose values are not user prose; only rule-file
// signatures (Log4Shell, Shellshock, scanners...) run on them.
var stdHeaders = map[string]bool{
	"accept": true, "accept-encoding": true, "accept-language": true, "connection": true,
	"content-length": true, "content-type": true, "host": true, "cache-control": true,
	"pragma": true, "upgrade-insecure-requests": true, "sec-fetch-site": true,
	"sec-fetch-mode": true, "sec-fetch-dest": true, "sec-fetch-user": true,
	"sec-ch-ua": true, "sec-ch-ua-mobile": true, "sec-ch-ua-platform": true,
	"if-none-match": true, "if-modified-since": true, "dnt": true, "te": true,
	"priority": true, "authorization": true, "x-request-id": true, "origin": true,
	"keep-alive": true, "transfer-encoding": true, "range": true, "if-match": true,
}

type collector struct{ ins []Input }

func (c *collector) add(loc, name, val string) {
	if val == "" || len(c.ins) >= maxInputs {
		return
	}
	c.ins = append(c.ins, Input{Location: loc, Name: name, Value: val})
}

// Extract returns every inspectable input of r. body is the already-read
// request body (the caller owns size limiting).
func Extract(r *http.Request, body []byte) []Input {
	c := &collector{ins: make([]Input, 0, 16)}

	p := r.URL.EscapedPath()
	c.add(locPath, "", p)
	for _, seg := range strings.Split(p, "/") {
		c.add(locSegment, "", seg)
	}

	if raw := r.URL.RawQuery; raw != "" {
		addReadings(c, parsediff.Query(raw), locQuery)
	}

	for name, vs := range r.Header {
		ln := strings.ToLower(name)
		if ln == "cookie" {
			for _, v := range vs {
				addCookies(c, v)
			}
			continue
		}
		loc := locHeader
		if stdHeaders[ln] {
			loc = locStdHdr
		}
		for _, v := range vs {
			c.add(loc, ln, v)
		}
	}

	if len(body) > 0 {
		mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if strings.Contains(mt, "xml") {
			c.add(locBodyRaw, "", string(body)) // DOCTYPE/ENTITY live outside elements
			if !walkXML(c, body) {
				c.add(locBody, "", string(body))
			}
		}
		// Every reading of the body (Go stdlib, strict, lenient framework
		// behaviours) is inspected, and disagreements between them are scored.
		addReadings(c, parsediff.Body(r.Header, body), locBody)
	}
	return c.ins
}

// addReadings turns a parsediff result into inputs.
func addReadings(c *collector, pr parsediff.Result, formLoc string) {
	for _, f := range pr.Fields {
		switch {
		case f.Key:
			c.add(locKey, f.Name, f.Value)
		case f.Kind == parsediff.KindJSON:
			c.add(locJSON, f.Name, f.Value)
		case f.Kind == parsediff.KindMultipart && f.HasFilename:
			c.add(locFilename, f.Name, f.Filename)
			c.add(locFile, f.Name, f.Value)
		case f.Kind == parsediff.KindMultipart && strings.HasPrefix(f.Name, "part-header:"):
			c.add(locHeader, strings.TrimPrefix(f.Name, "part-header:"), f.Value)
		case f.Kind == parsediff.KindQuery:
			c.add(locQuery, f.Name, f.Value)
		default:
			c.add(formLoc, f.Name, f.Value)
		}
	}
	for _, a := range pr.Ambiguities {
		if len(c.ins) < maxInputs {
			c.ins = append(c.ins, Input{Location: locParseDiff, Name: a.Code, Value: a.Detail, score: a.Score})
		}
	}
}

// addCookies parses a Cookie header leniently. net/http silently drops cookie
// values containing characters like quotes or spaces, which is exactly what
// injection payloads contain.
func addCookies(c *collector, header string) {
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, val, ok := strings.Cut(part, "=")
		if !ok {
			c.add(locCookie, "", part)
			continue
		}
		c.add(locKey, "cookie", name)
		c.add(locCookie, name, val)
	}
}

func walkXML(c *collector, body []byte) bool {
	d := xml.NewDecoder(bytes.NewReader(body))
	d.Strict = false
	d.AutoClose = xml.HTMLAutoClose
	d.Entity = xml.HTMLEntity
	n := 0
	for n < maxInputs {
		tok, err := d.Token()
		if err != nil {
			return n > 0
		}
		switch t := tok.(type) {
		case xml.StartElement:
			for _, a := range t.Attr {
				c.add(locXML, a.Name.Local, a.Value)
				n++
			}
		case xml.CharData:
			if s := strings.TrimSpace(string(t)); s != "" {
				c.add(locXML, "", s)
				n++
			}
		case xml.Comment:
			c.add(locXML, "#comment", string(t))
			n++
		}
	}
	return true
}
