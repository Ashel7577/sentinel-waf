package parsediff

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
)

const payload = "1' UNION SELECT password FROM users--"

func hdr(ct ...string) http.Header {
	h := http.Header{}
	for _, c := range ct {
		h.Add("Content-Type", c)
	}
	return h
}

func hasValue(r Result, v string) bool {
	for _, f := range r.Fields {
		if strings.Contains(f.Value, v) || strings.Contains(f.Filename, v) {
			return true
		}
	}
	return false
}

func hasAmb(r Result, code string) bool {
	for _, a := range r.Ambiguities {
		if a.Code == code {
			return true
		}
	}
	return false
}

func stdMultipart(t *testing.T, fields map[string]string, file string) (string, []byte) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range fields {
		_ = w.WriteField(k, v)
	}
	if file != "" {
		fw, _ := w.CreateFormFile("upload", file)
		_, _ = fw.Write([]byte("hello\r\nworld\r\n"))
	}
	_ = w.Close()
	return w.FormDataContentType(), buf.Bytes()
}

// Well-formed bodies produced by real encoders must not raise anything.
func TestBenignNoAmbiguity(t *testing.T) {
	ct, body := stdMultipart(t, map[string]string{"user": "O'Reilly", "comment": "line one\r\nline two\r\n"}, "report.pdf")
	cases := []struct {
		name string
		h    http.Header
		body string
	}{
		{"multipart", hdr(ct), string(body)},
		{"json", hdr("application/json"), `{"user":"ann","tags":["a","b"],"n":5,"nested":{"x":"y"}}`},
		{"json-charset", hdr("application/json; charset=utf-8"), `{"q":"select a plan"}`},
		{"form", hdr("application/x-www-form-urlencoded"), "a=1&b=two+words&c=%27x%27"},
		{"form-array", hdr("application/x-www-form-urlencoded"), "tag=a&tag=a"},
	}
	for _, c := range cases {
		r := Body(c.h, []byte(c.body))
		if len(r.Ambiguities) != 0 {
			t.Errorf("%s: unexpected ambiguities %+v", c.name, r.Ambiguities)
		}
		if len(r.Fields) == 0 {
			t.Errorf("%s: no fields", c.name)
		}
	}
	if r := Query("q=hello+world&page=2"); len(r.Ambiguities) != 0 {
		t.Errorf("query: %+v", r.Ambiguities)
	}
}

// Each case hides the payload with a structural trick. The payload must be
// in the union of fields (so the detectors see it) and the trick must be
// reported.
func TestBypassClasses(t *testing.T) {
	cases := []struct {
		name string
		h    http.Header
		body string
		code string
	}{
		{"json-dup-key", hdr("application/json"), `{"q":"` + payload + `","q":"hello"}`, "json-dup-key"},
		{"json-case-dup", hdr("application/json"), `{"role":"user","ROLE":"` + payload + `"}`, "json-case-dup-key"},
		{"json-trailing", hdr("application/json"), `{"q":"hello"}{"q":"` + payload + `"}`, "json-trailing-data"},
		{"json-comments", hdr("application/json"), `{"q":"hello", /* hi */ "x":"` + payload + `",}`, "json-nonstandard"},
		{"json-bom", hdr("application/json"), "\xef\xbb\xbf" + `{"q":"` + payload + `"}`, "json-bom"},
		{"multipart-two-boundaries", hdr(`multipart/form-data; boundary=AAA; boundary=BBB`),
			"--BBB\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n" + payload + "\r\n--BBB--\r\n", "multipart-boundary-ambiguous"},
		{"multipart-after-close", hdr("multipart/form-data; boundary=XX"),
			"--XX\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nhello\r\n--XX--\r\n--XX\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n" + payload + "\r\n--XX--\r\n",
			"multipart-after-close"},
		{"multipart-dup-name", hdr("multipart/form-data; boundary=XX"),
			"--XX\r\nContent-Disposition: form-data; name=\"safe\"; name=\"q\"\r\n\r\n" + payload + "\r\n--XX--\r\n", "multipart-dup-param"},
		{"multipart-lf", hdr("multipart/form-data; boundary=XX"),
			"--XX\nContent-Disposition: form-data; name=\"q\"\n\n" + payload + "\n--XX--\n", "multipart-lf-line-endings"},
		{"multipart-filename-star", hdr("multipart/form-data; boundary=XX"),
			"--XX\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"; filename*=UTF-8''..%2F..%2Fetc%2Fpasswd\r\n\r\nx\r\n--XX--\r\n", "multipart-filename-conflict"},
		{"multipart-unterminated", hdr("multipart/form-data; boundary=XX"),
			"--XX\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n" + payload, "multipart-unterminated"},
		{"two-content-types", hdr("application/x-www-form-urlencoded", "application/json"), `{"q":"` + payload + `"}`, "content-type-duplicate"},
		{"declared-form-body-json", hdr("application/x-www-form-urlencoded"), `{"q":"` + payload + `"}`, "content-type-mismatch"},
		{"ebcdic-charset", hdr("application/x-www-form-urlencoded; charset=ibm037"), "q=%88%85%93%93%96", "body-charset"},
		{"form-semicolon", hdr("application/x-www-form-urlencoded"), "a=1;q=" + strings.ReplaceAll(payload, " ", "+"), "form-semicolon-separator"},
	}
	for _, c := range cases {
		r := Body(c.h, []byte(c.body))
		if !hasAmb(r, c.code) {
			t.Errorf("%s: expected %s, got %+v", c.name, c.code, r.Ambiguities)
		}
		if c.code != "body-charset" && c.code != "multipart-filename-conflict" && !hasValue(r, "UNION SELECT") {
			t.Errorf("%s: payload missing from union of fields", c.name)
		}
	}
	// filename* payload must be decoded and visible
	r := Body(hdr("multipart/form-data; boundary=XX"),
		[]byte("--XX\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"; filename*=UTF-8''..%2F..%2Fetc%2Fpasswd\r\n\r\nx\r\n--XX--\r\n"))
	if !hasValue(r, "../../etc/passwd") {
		t.Errorf("filename* not decoded: %+v", r.Fields)
	}
}

// HTTP parameter pollution: the payload only exists after joining duplicates.
func TestParameterPollutionJoin(t *testing.T) {
	r := Query("q=1'/*&q=*/UNION/*&q=*/SELECT+1--")
	if !hasValue(r, "1'/*,*/UNION/*,*/SELECT 1--") {
		t.Errorf("comma-join reading missing: %+v", r.Fields)
	}
}

// The Go reading must match what net/http hands a Go handler.
func TestGoReadingMatchesNetHTTP(t *testing.T) {
	ct, body := stdMultipart(t, map[string]string{"a": "x", "b": "y z"}, "")
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", ct)
	if err := req.ParseMultipartForm(1 << 20); err != nil {
		t.Fatal(err)
	}
	r := Body(hdr(ct), body)
	for k, vs := range req.MultipartForm.Value {
		for _, v := range vs {
			found := false
			for _, f := range r.Fields {
				if f.Reading == "go" && f.Name == k && f.Value == v {
					found = true
				}
			}
			if !found {
				t.Errorf("net/http sees %s=%q, Go reading does not", k, v)
			}
		}
	}
}

func FuzzBody(f *testing.F) {
	f.Add("multipart/form-data; boundary=XX", "--XX\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nv\r\n--XX--\r\n")
	f.Add("application/json", `{"a":[1,{"b":"c"}],"a":"d"}`)
	f.Add("application/x-www-form-urlencoded", "a=1&a=2;b=%zz")
	f.Fuzz(func(t *testing.T, ct, body string) {
		_ = Body(hdr(ct), []byte(body))
		_ = Query(body)
	})
}
