package parsediff

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

var reBoundary = regexp.MustCompile(`(?i)boundary\s*=\s*(?:"([^"]*)"|([^;,\s]+))`)

// multipartReadings reads a multipart body.
//
// Readings:
//   - go: mime/multipart, exactly what r.ParseMultipartForm gives a Go backend
//     (including its automatic quoted-printable decoding).
//   - lenient: a line scanner that accepts LF-only line endings, header
//     folding, a delimiter that is only a prefix of the line, both copies of a
//     duplicated Content-Disposition parameter, filename* (RFC 5987) and parts
//     placed after the closing delimiter. Several popular parsers accept
//     each of these.
//
// Every candidate boundary is tried (the strict one from the header, every
// boundary= occurrence in the raw header, and the first delimiter line of the
// body), and the field sets of the readings are compared.
func multipartReadings(a *acc, ct string, body []byte) {
	var cands []string
	strict := ""
	if _, p, err := mime.ParseMediaType(ct); err == nil {
		strict = p["boundary"]
	}
	add := func(b string) {
		if b == "" || len(b) > 200 {
			return
		}
		for _, c := range cands {
			if c == b {
				return
			}
		}
		cands = append(cands, b)
	}
	add(strict)
	for _, m := range reBoundary.FindAllStringSubmatch(ct, -1) {
		add(m[1] + m[2])
	}
	headerCands := len(cands)
	if b := firstDelimiter(body); b != "" {
		if headerCands == 0 {
			add(b)
		} else if b != cands[0] {
			found := false
			for _, c := range cands {
				if c == b {
					found = true
				}
			}
			if !found && strings.HasPrefix(b, cands[0]) {
				// body delimiter extends the declared boundary: prefix-matching
				// parsers split on it, exact ones do not
				a.amb("multipart-boundary-prefix", Critical, "first delimiter in the body only starts with the declared boundary; prefix-matching parsers split parts differently")
			}
		}
	}
	if headerCands > 1 {
		a.amb("multipart-boundary-ambiguous", Critical,
			"Content-Type declares "+itoa(headerCands)+" different boundaries; parsers that take the first and parsers that take the last split the body differently")
	}
	if len(cands) == 0 {
		a.amb("multipart-no-boundary", Warning, "multipart body without a usable boundary")
		a.field(Field{Kind: KindRaw, Name: "body", Value: string(body), Reading: "raw"})
		return
	}

	for i, b := range cands {
		goSet := goMultipart(a, body, b)
		lenSet := lenientMultipart(a, body, b)
		if i == 0 && !sameSet(goSet, lenSet) {
			a.amb("multipart-parser-disagree", Critical,
				"Go's mime/multipart and a lenient parser extract different fields from this body ("+
					itoa(len(goSet))+" vs "+itoa(len(lenSet))+" fields)")
		}
	}
}

func firstDelimiter(body []byte) string {
	for _, line := range bytes.SplitN(body, []byte("\n"), 64) {
		l := strings.TrimRight(string(line), "\r \t")
		if strings.HasPrefix(l, "--") && len(l) > 2 {
			return strings.TrimSuffix(l[2:], "--")
		}
	}
	return ""
}

type fieldKey struct{ name, value, filename string }

func sameSet(x, y map[fieldKey]bool) bool {
	if len(x) != len(y) {
		return false
	}
	for k := range x {
		if !y[k] {
			return false
		}
	}
	return true
}

func goMultipart(a *acc, body []byte, boundary string) map[fieldKey]bool {
	set := map[fieldKey]bool{}
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	n := 0
	for n < maxFields {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		n++
		// FormName/FileName as Go uses them (FileName applies filepath.Base,
		// so take the raw parameter to keep "../" visible to the detectors).
		name := part.FormName()
		_, dp, _ := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		fn, hasFn := dp["filename"]
		data, _ := io.ReadAll(io.LimitReader(part, maxPart))
		emitPart(a, name, string(data), fn, hasFn, "go")
		set[fieldKey{name, string(data), fn}] = true
		for hk, hv := range part.Header {
			if !strings.EqualFold(hk, "Content-Disposition") && !strings.EqualFold(hk, "Content-Type") {
				a.field(Field{Kind: KindMultipart, Name: "part-header:" + strings.ToLower(hk), Value: strings.Join(hv, ","), Reading: "go"})
			}
		}
	}
	if n > 0 {
		a.reading("go")
	}
	return set
}

func emitPart(a *acc, name, value, filename string, hasFn bool, reading string) {
	a.field(Field{Kind: KindMultipart, Name: "multipart", Value: name, Key: true, Reading: reading})
	a.field(Field{Kind: KindMultipart, Name: name, Value: value, Filename: filename, HasFilename: hasFn, Reading: reading})
}

type rawLine struct {
	text string // without line ending
	crlf bool
}

func splitLines(body []byte) []rawLine {
	var out []rawLine
	for len(body) > 0 {
		i := bytes.IndexByte(body, '\n')
		if i < 0 {
			out = append(out, rawLine{text: string(body)})
			break
		}
		l := body[:i]
		crlf := len(l) > 0 && l[len(l)-1] == '\r'
		if crlf {
			l = l[:len(l)-1]
		}
		out = append(out, rawLine{text: string(l), crlf: crlf})
		body = body[i+1:]
	}
	return out
}

func lenientMultipart(a *acc, body []byte, boundary string) map[fieldKey]bool {
	set := map[fieldKey]bool{}
	delim := "--" + boundary
	lines := splitLines(body)
	lfOnly, closed, afterClose, partsAfter := false, false, false, 0

	type part struct {
		hdr   []string
		inHdr bool
		body  []rawLine
	}
	var cur *part
	finish := func() {
		if cur == nil {
			return
		}
		var b strings.Builder
		for i, l := range cur.body {
			b.WriteString(l.text)
			if i < len(cur.body)-1 {
				if l.crlf {
					b.WriteString("\r\n")
				} else {
					b.WriteString("\n")
				}
			}
		}
		lenientPart(a, set, cur.hdr, b.String())
		if afterClose {
			partsAfter++
		}
		cur = nil
	}
	for i, l := range lines {
		t := strings.TrimRight(l.text, " \t")
		if strings.HasPrefix(t, delim) {
			rest := t[len(delim):]
			if !l.crlf && i < len(lines)-1 {
				lfOnly = true
			}
			finish()
			if strings.HasPrefix(rest, "--") {
				if closed {
					continue
				}
				closed = true
				continue
			}
			if closed {
				afterClose = true
			}
			cur = &part{inHdr: true}
			continue
		}
		if cur == nil {
			continue // preamble / epilogue text
		}
		if cur.inHdr {
			if l.text == "" {
				cur.inHdr = false
				continue
			}
			if (l.text[0] == ' ' || l.text[0] == '\t') && len(cur.hdr) > 0 {
				cur.hdr[len(cur.hdr)-1] += " " + strings.TrimSpace(l.text) // folded header
				continue
			}
			cur.hdr = append(cur.hdr, l.text)
			continue
		}
		cur.body = append(cur.body, l)
	}
	if cur != nil {
		finish()
		if !closed {
			a.amb("multipart-unterminated", Warning, "multipart body has no closing delimiter; some parsers drop the last part, others keep it")
		}
	}
	if lfOnly {
		a.amb("multipart-lf-line-endings", Warning, "multipart delimiters end in LF instead of CRLF; strict parsers fail, lenient ones accept")
	}
	if partsAfter > 0 {
		a.amb("multipart-after-close", Critical, itoa(partsAfter)+" part(s) after the closing delimiter; parsers that keep reading see fields the others ignore")
	}
	if len(set) > 0 {
		a.reading("lenient")
	}
	return set
}

// lenientPart parses one part's headers the permissive way and emits fields.
func lenientPart(a *acc, set map[fieldKey]bool, hdr []string, value string) {
	var cd string
	for _, h := range hdr {
		k, v, ok := strings.Cut(h, ":")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		switch k {
		case "content-disposition":
			if cd == "" {
				cd = v
			}
		case "content-type":
		default:
			a.field(Field{Kind: KindMultipart, Name: "part-header:" + k, Value: v, Reading: "lenient"})
		}
	}
	params := cdParams(cd)
	names := params["name"]
	fns := params["filename"]
	fnStar := params["filename*"]
	if len(distinct(names)) > 1 {
		a.amb("multipart-dup-param", Critical, "Content-Disposition has several different name= values; parsers keep the first, the last, or reject")
	}
	if len(distinct(fns)) > 1 {
		a.amb("multipart-dup-filename", Critical, "Content-Disposition has several different filename= values")
	}
	for _, s := range fnStar {
		dec := rfc5987(s)
		fns = append(fns, dec)
		if len(params["filename"]) > 0 && dec != params["filename"][0] {
			a.amb("multipart-filename-conflict", Critical, "filename and filename* disagree; RFC 6266 parsers prefer filename*, others use filename")
		}
	}
	if len(names) == 0 {
		names = []string{""}
	}
	hasFn := len(fns) > 0
	for _, n := range distinct(names) {
		if hasFn {
			for _, f := range distinct(fns) {
				emitPart(a, n, value, f, true, "lenient")
			}
		} else {
			emitPart(a, n, value, "", false, "lenient")
		}
	}
	// set used for the consensus check: the reading a typical lenient parser
	// produces (last name= wins, plain filename)
	name := names[len(names)-1]
	fn := ""
	if len(params["filename"]) > 0 {
		fn = params["filename"][len(params["filename"])-1]
	} else if hasFn {
		fn = fns[0]
	}
	_ = hasFn
	set[fieldKey{name, value, fn}] = true
}

// cdParams parses Content-Disposition parameters keeping every occurrence.
func cdParams(cd string) map[string][]string {
	out := map[string][]string{}
	var parts []string
	inQ, start := false, 0
	for i := 0; i < len(cd); i++ {
		switch cd[i] {
		case '"':
			if i == 0 || cd[i-1] != '\\' {
				inQ = !inQ
			}
		case ';':
			if !inQ {
				parts = append(parts, cd[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, cd[start:])
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			v = strings.ReplaceAll(v[1:len(v)-1], `\"`, `"`)
		}
		out[k] = append(out[k], v)
	}
	return out
}

// rfc5987 decodes charset'lang'percent-encoded (filename*=UTF-8”%2e%2e%2f...).
func rfc5987(s string) string {
	parts := strings.SplitN(s, "'", 3)
	if len(parts) != 3 {
		return s
	}
	if v, err := url.PathUnescape(parts[2]); err == nil {
		return v
	}
	return lenientUnescape(parts[2])
}

func distinct(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
