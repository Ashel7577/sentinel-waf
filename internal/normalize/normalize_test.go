package normalize

import "testing"

func TestValue(t *testing.T) {
	cases := map[string]string{
		"%27%20OR%201%3D1":    "' or 1=1",
		"%2527%2520OR":        "' or",             // double encoding
		"%252527":             "'",                // triple encoding
		"&lt;script&gt;":      "<script>",         // HTML entities
		"&#x3c;svg&#62;":      "<svg>",            // numeric entities
		`\x3cscript\u003e`:    "<script>",         // JS escapes
		"%u003cscript%u003e":  "<script>",         // IIS %u
		"ＳＥＬＥＣＴ":              "select",           // fullwidth
		"a\t\t b":             "a b",              // whitespace collapse
		"a\r\n\r\nb":          "a\nb",             // newlines kept for shells
		"un\x00ion":           "union",            // NUL removed
		"..%c0%af..%c0%afetc": "../../etc",        // overlong UTF-8
		"100% cotton":         "100% cotton",      // malformed escape kept
		"C:\\xampp\\users":    "c:\\xampp\\users", // not a valid \x escape
	}
	for in, want := range cases {
		if got := Value(in); got != want {
			t.Errorf("Value(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStripSQLComments(t *testing.T) {
	cases := map[string]string{
		"union/**/select":             "union select",
		"/*!50000union*/ /*!select*/": " union   select ",
		"a/* unterminated":            "a /*",
		"no comments":                 "no comments",
	}
	for in, want := range cases {
		if got := StripSQLComments(in); got != want {
			t.Errorf("StripSQLComments(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCompact(t *testing.T) {
	if got := Compact("java\tscr\nipt :"); got != "javascript:" {
		t.Errorf("got %q", got)
	}
}
