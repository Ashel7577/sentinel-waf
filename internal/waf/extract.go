package waf

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Input is one attacker-controllable value pulled out of a request.
type Input struct {
	Location string // see the loc* constants
	Name     string // parameter / header / JSON path
	Value    string
}

// Input locations. They decide which analysers run on a value.
const (
	locPath     = "path"         // whole path: traversal + rules
	locSegment  = "path-segment" // one decoded path segment: full analysis
	locQuery    = "query"
	locBody     = "body"
	locJSON     = "json"
	locXML      = "xml"
	locCookie   = "cookie"
	locHeader   = "header"     // non-standard header: full analysis
	locStdHdr   = "header-std" // well-known header: rules only
	locKey      = "key"        // parameter / JSON key names
	locFilename = "filename"   // multipart upload filename (raw, not basename'd)
	locFile     = "file"       // uploaded file content: rules only
	locBodyRaw  = "body-raw"   // entire raw body: rules only (XXE, etc.)
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
		addForm(c, raw, "query", locQuery)
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
		mt, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		trimmed := bytes.TrimSpace(body)
		switch {
		case mt == "application/x-www-form-urlencoded":
			addForm(c, string(body), "form", locBody)
		case mt == "application/json" || strings.HasSuffix(mt, "+json") ||
			(mt == "" && len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')):
			if !walkJSON(c, body) {
				c.add(locBody, "", string(body))
			}
		case strings.HasPrefix(mt, "multipart/"):
			if !walkMultipart(c, body, params["boundary"]) {
				c.add(locBody, "", string(body))
			}
		case strings.Contains(mt, "xml"):
			c.add(locBodyRaw, "", string(body)) // DOCTYPE/ENTITY live outside elements
			if !walkXML(c, body) {
				c.add(locBody, "", string(body))
			}
		default:
			c.add(locBody, "", string(body))
		}
	}
	return c.ins
}

// addForm parses a urlencoded string. Go's parser drops pairs it considers
// malformed (bad escapes, ';'), which an attacker could abuse to hide a
// payload, so on any parse error the raw string is inspected as well.
func addForm(c *collector, raw, keySrc, loc string) {
	vals, err := url.ParseQuery(raw)
	for k, vs := range vals {
		c.add(locKey, keySrc, k)
		for _, v := range vs {
			c.add(loc, k, v)
		}
	}
	if err != nil {
		c.add(loc, "", raw)
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

func walkJSON(c *collector, data []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return false
	}
	var walk func(path string, v any, depth int)
	walk = func(path string, v any, depth int) {
		if depth > maxDepth {
			return
		}
		switch t := v.(type) {
		case map[string]any:
			for k, x := range t {
				c.add(locKey, "json", k)
				walk(path+"."+k, x, depth+1)
			}
		case []any:
			for i, x := range t {
				walk(path+"["+strconv.Itoa(i)+"]", x, depth+1)
			}
		case string:
			c.add(locJSON, path, t)
		}
	}
	walk("$", v, 0)
	return true
}

func walkMultipart(c *collector, body []byte, boundary string) bool {
	if boundary == "" {
		return false
	}
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	n := 0
	for {
		part, err := mr.NextPart()
		if err != nil {
			return n > 0 || err == io.EOF
		}
		n++
		// Part.FileName() applies filepath.Base and would hide "../../shell.php".
		_, dp, _ := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		name := dp["name"]
		data, _ := io.ReadAll(io.LimitReader(part, maxPart))
		c.add(locKey, "multipart", name)
		if fn, ok := dp["filename"]; ok {
			c.add(locFilename, name, fn)
			c.add(locFile, name, string(data))
		} else {
			c.add(locBody, name, string(data))
		}
		for hk, hv := range part.Header {
			if !strings.EqualFold(hk, "Content-Disposition") && !strings.EqualFold(hk, "Content-Type") {
				c.add(locHeader, strings.ToLower(hk), strings.Join(hv, ","))
			}
		}
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
