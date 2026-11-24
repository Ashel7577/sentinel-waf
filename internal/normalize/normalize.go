// Package normalize turns attacker-controlled input into a canonical form so
// detectors see what the backend will eventually interpret, regardless of the
// encoding tricks used to smuggle it past pattern matching.
package normalize

import (
	"html"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxPasses bounds multi-layer decoding (e.g. %25252e) so a hostile input
// cannot make us loop for long.
const maxPasses = 4

// Value fully decodes s (bounded) and returns its canonical form:
// lower-cased, NUL bytes removed, fullwidth ASCII folded, runs of horizontal
// whitespace collapsed to one space and runs of CR/LF collapsed to one '\n'
// (newlines are kept because they are command separators for shells).
func Value(s string) string {
	prev := s
	for i := 0; i < maxPasses; i++ {
		cur := decodeOnce(prev)
		if cur == prev {
			break
		}
		prev = cur
	}
	return canonical(prev)
}

// Compact removes every whitespace and control character. Browsers ignore
// tabs/newlines inside URL schemes, so "java\tscript:" must match "javascript:".
func Compact(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

// StripSQLComments replaces /* ... */ comments with a space so that
// "UNION/**/SELECT" tokenizes like "UNION SELECT". MySQL executable comments
// (/*!50000 UNION */) are unwrapped because MySQL runs their contents.
func StripSQLComments(s string) string {
	if !strings.Contains(s, "/*") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for {
		i := strings.Index(s, "/*")
		if i < 0 {
			b.WriteString(s)
			break
		}
		b.WriteString(s[:i])
		rest := s[i+2:]
		j := strings.Index(rest, "*/")
		inner := rest
		if j >= 0 {
			inner = rest[:j]
		}
		b.WriteByte(' ')
		if strings.HasPrefix(inner, "!") {
			b.WriteString(strings.TrimLeft(inner[1:], "0123456789"))
			b.WriteByte(' ')
		}
		if j < 0 {
			b.WriteString("/*") // keep the unterminated comment: it is a terminator signal
			break
		}
		s = rest[j+2:]
	}
	return b.String()
}

func decodeOnce(s string) string {
	s = percentDecode(s)
	if strings.IndexByte(s, '&') >= 0 {
		s = html.UnescapeString(s)
	}
	s = backslashDecode(s)
	s = overlongDecode(s)
	return s
}

// percentDecode is a lenient URL decoder: %XX and IIS-style %uXXXX are decoded,
// malformed escapes are left as-is (a strict decoder would reject them and let
// the payload through untouched).
func percentDecode(s string) string {
	if strings.IndexByte(s, '%') < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' {
			if i+6 <= len(s) && (s[i+1] == 'u' || s[i+1] == 'U') {
				if v, ok := hexVal(s[i+2 : i+6]); ok {
					b.WriteRune(rune(v))
					i += 5
					continue
				}
			}
			if i+3 <= len(s) {
				if v, ok := hexVal(s[i+1 : i+3]); ok {
					b.WriteByte(byte(v))
					i += 2
					continue
				}
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

// backslashDecode handles JavaScript/C style \xNN and \uNNNN escapes.
func backslashDecode(s string) string {
	if !strings.Contains(s, `\x`) && !strings.Contains(s, `\u`) &&
		!strings.Contains(s, `\X`) && !strings.Contains(s, `\U`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'x', 'X':
				if i+4 <= len(s) {
					if v, ok := hexVal(s[i+2 : i+4]); ok {
						b.WriteByte(byte(v))
						i += 3
						continue
					}
				}
			case 'u', 'U':
				if i+6 <= len(s) {
					if v, ok := hexVal(s[i+2 : i+6]); ok {
						b.WriteRune(rune(v))
						i += 5
						continue
					}
				}
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// overlongDecode maps invalid overlong UTF-8 encodings of '/' and '\' that
// some legacy decoders accept (the classic %c0%af traversal bypass).
var overlong = strings.NewReplacer(
	"\xc0\xaf", "/", "\xe0\x80\xaf", "/", "\xc0\x2f", "/",
	"\xc0\x5c", `\`, "\xc1\x9c", `\`, "\xc0\x2e", ".", "\xc0\xae", ".",
)

func overlongDecode(s string) string {
	if strings.IndexByte(s, 0xc0) < 0 && strings.IndexByte(s, 0xc1) < 0 && strings.IndexByte(s, 0xe0) < 0 {
		return s
	}
	return overlong.Replace(s)
}

// confusables are look-alike code points that "best-fit" decoders (Windows,
// IIS, some ORMs) convert to their ASCII meta-character, which makes them a
// classic filter bypass: %u2215 becomes '/', U+02BC becomes a quote.
var confusables = map[rune]rune{
	0x2215: '/', 0x2044: '/', 0x29F8: '/', 0x2571: '/',
	0x2216: '\\', 0x29F9: '\\', 0xFE68: '\\', 0x2572: '\\',
	0x2024: '.', 0xFE52: '.', 0x3002: '.',
	0x02BC: '\'', 0x02B9: '\'', 0x2018: '\'', 0x2019: '\'', 0x2032: '\'', 0x00B4: '\'',
	0x201C: '"', 0x201D: '"', 0x2033: '"', 0x02BA: '"',
	0xFE64: '<', 0x02C2: '<', 0x2039: '<', 0x3008: '<',
	0xFE65: '>', 0x02C3: '>', 0x203A: '>', 0x3009: '>',
	0xFE54: ';', 0x037E: ';',
	0xFE59: '(', 0xFE5A: ')', 0x2768: '(', 0x2769: ')',
}

func canonical(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	last := byte(0) // last whitespace byte written: ' ', '\n' or 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if r == utf8.RuneError && size == 1 {
			b.WriteByte(s[i-1])
			last = 0
			continue
		}
		if r >= 0xFF01 && r <= 0xFF5E { // fullwidth ASCII variants
			r -= 0xFEE0
		} else if m, ok := confusables[r]; ok {
			r = m
		}
		switch {
		case r == 0:
			continue
		case r == '\n' || r == '\r':
			if last != '\n' {
				b.WriteByte('\n')
				last = '\n'
			}
			continue
		case unicode.IsSpace(r) || unicode.IsControl(r) || r == 0xA0:
			if last == 0 {
				b.WriteByte(' ')
				last = ' '
			}
			continue
		}
		last = 0
		b.WriteRune(unicode.ToLower(r))
	}
	return strings.Trim(b.String(), " ")
}

func hexVal(h string) (int, bool) {
	v := 0
	for i := 0; i < len(h); i++ {
		c := h[i]
		switch {
		case c >= '0' && c <= '9':
			v = v<<4 | int(c-'0')
		case c >= 'a' && c <= 'f':
			v = v<<4 | int(c-'a'+10)
		case c >= 'A' && c <= 'F':
			v = v<<4 | int(c-'A'+10)
		default:
			return 0, false
		}
	}
	return v, true
}
