package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Ashel7577/sentinel-waf/internal/waf"
)

func setup(t *testing.T, opts Options) (*httptest.Server, *Server) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Seen-Score", r.Header.Get("X-WAF-Score"))
		w.Write(b)
	}))
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	opts.Upstream = u
	s := New(opts, waf.NewEngine(waf.Config{}, waf.DefaultRules()))
	front := httptest.NewServer(s)
	t.Cleanup(front.Close)
	return front, s
}

func TestBlocksAndForwards(t *testing.T) {
	front, s := setup(t, Options{})

	resp, err := http.Get(front.URL + "/search?q=" + url.QueryEscape("' OR 1=1--"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("attack: status %d, want 403", resp.StatusCode)
	}
	if resp.Header.Get("X-Request-ID") == "" {
		t.Error("missing X-Request-ID")
	}

	resp, err = http.Post(front.URL+"/echo", "text/plain", strings.NewReader("hello O'Brien"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "hello O'Brien" {
		t.Errorf("benign: status %d body %q — body must reach upstream intact", resp.StatusCode, body)
	}
	if st := s.Metrics.snapshot(0, 60); st.Requests != 2 || st.Blocked != 1 {
		t.Errorf("metrics: %+v", st)
	}
}

func TestMonitorMode(t *testing.T) {
	front, s := setup(t, Options{Monitor: true})
	resp, err := http.Get(front.URL + "/?q=" + url.QueryEscape("<script>alert(1)</script>"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("monitor mode must forward, got %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Seen-Score") == "" {
		t.Error("upstream should receive X-WAF-Score")
	}
	if s.Metrics.flagged.Load() != 1 {
		t.Error("request should be counted as flagged")
	}
}

func TestBodyLimit(t *testing.T) {
	front, _ := setup(t, Options{MaxBody: 10})
	resp, err := http.Post(front.URL+"/", "text/plain", strings.NewReader(strings.Repeat("a", 11)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status %d, want 413", resp.StatusCode)
	}
}

func TestRateLimit(t *testing.T) {
	front, _ := setup(t, Options{RateLimit: 1, Burst: 2})
	codes := []int{}
	for i := 0; i < 4; i++ {
		resp, err := http.Get(front.URL + "/")
		if err != nil {
			t.Fatal(err)
		}
		codes = append(codes, resp.StatusCode)
	}
	if codes[0] != 200 || codes[1] != 200 || codes[3] != http.StatusTooManyRequests {
		t.Errorf("codes %v", codes)
	}
}

func TestAdmin(t *testing.T) {
	_, s := setup(t, Options{})
	admin := httptest.NewServer(s.AdminHandler())
	defer admin.Close()
	for _, p := range []string{"/", "/stats", "/metrics", "/healthz"} {
		resp, err := http.Get(admin.URL + p)
		if err != nil || resp.StatusCode != 200 {
			t.Errorf("%s: %v %v", p, err, resp)
		}
	}
	resp, _ := http.Get(admin.URL + "/metrics")
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "waf_inspect_duration_seconds_bucket") {
		t.Error("prometheus histogram missing")
	}
}
