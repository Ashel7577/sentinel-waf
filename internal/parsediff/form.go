package parsediff

import (
	"net/url"
	"strings"
)

// form reads a urlencoded string (query string or form body).
//
// Readings:
//   - go: net/url.ParseQuery, exactly what a Go backend's r.Form holds.
//     Go drops pairs it cannot decode and, since Go 1.17, pairs split by ';'.
//   - lenient: split on '&', decode leniently (invalid escapes kept literally),
//     so a value Go silently drops is still inspected.
//   - semicolon: split on '&' AND ';' (older Go, Python < 3.9.2, some Java
//     servlet containers), only when the raw string has an unescaped ';'.
//   - comma-join: duplicate names joined with ',' the way ASP.NET builds
//     Request["x"]. A payload split across x=a&x=b (HTTP parameter
//     pollution) is only visible after joining.
func form(a *acc, raw, kind string) {
	if raw == "" {
		return
	}
	vals, err := url.ParseQuery(raw)
	got := false
	for k, vs := range vals {
		a.field(Field{Kind: kind, Name: kind, Value: k, Key: true, Reading: "go"})
		for _, v := range vs {
			a.field(Field{Kind: kind, Name: k, Value: v, Reading: "go"})
		}
		got = true
	}
	if got {
		a.reading("go")
	}

	lenient := splitPairs(raw, "&")
	for _, p := range lenient {
		a.field(Field{Kind: kind, Name: kind, Value: p[0], Key: true, Reading: "lenient"})
		a.field(Field{Kind: kind, Name: p[0], Value: p[1], Reading: "lenient"})
	}
	if err != nil {
		a.reading("lenient")
		if strings.Contains(raw, ";") {
			for _, p := range splitPairs(raw, "&;") {
				a.field(Field{Kind: kind, Name: kind, Value: p[0], Key: true, Reading: "semicolon"})
				a.field(Field{Kind: kind, Name: p[0], Value: p[1], Reading: "semicolon"})
			}
			a.reading("semicolon")
			a.amb(kind+"-semicolon-separator", Warning,
				"unescaped ';' in "+kind+": Go ignores those pairs, older Python/Java servers treat ';' as a separator")
		} else {
			a.amb(kind+"-bad-escape", Notice,
				"malformed percent-escape in "+kind+": Go drops the pair, other parsers keep it literally")
		}
	}

	// Duplicate names: inspect the joined value too.
	byName := map[string][]string{}
	var order []string
	for _, p := range lenient {
		if _, ok := byName[p[0]]; !ok {
			order = append(order, p[0])
		}
		byName[p[0]] = append(byName[p[0]], p[1])
	}
	joined := false
	for _, k := range order {
		vs := byName[k]
		if len(vs) < 2 {
			continue
		}
		distinct := map[string]bool{}
		for _, v := range vs {
			distinct[v] = true
		}
		if len(distinct) < 2 {
			continue
		}
		a.field(Field{Kind: kind, Name: k, Value: strings.Join(vs, ","), Reading: "comma-join"})
		joined = true
	}
	if joined {
		a.reading("comma-join")
	}
}

// splitPairs splits on any of seps and decodes names and values leniently.
func splitPairs(raw, seps string) [][2]string {
	var out [][2]string
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return strings.ContainsRune(seps, r) }) {
		k, v, _ := strings.Cut(part, "=")
		out = append(out, [2]string{lenientUnescape(k), lenientUnescape(v)})
		if len(out) >= maxFields {
			break
		}
	}
	return out
}

// lenientUnescape decodes %XX and '+', keeping invalid escapes as literal text.
func lenientUnescape(s string) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '+':
			b.WriteByte(' ')
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}
