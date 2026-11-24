// Package server is the reverse-proxy front end: it reads and size-limits the
// request, runs the inspection engine, and either blocks or forwards.
package server

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Ashel7577/sentinel-waf/internal/waf"
)

// Options configures the proxy.
type Options struct {
	Upstream  *url.URL
	Monitor   bool  // log only, never block (shadow mode)
	MaxBody   int64 // bytes
	RateLimit float64
	Burst     int
	TrustXFF  bool // take client IP from X-Forwarded-For (only behind a trusted LB)
	LogAll    bool
	Logger    *slog.Logger
}

// Server is an http.Handler.
type Server struct {
	opts    Options
	engine  *waf.Engine
	proxy   *httputil.ReverseProxy
	limiter *RateLimiter
	Metrics *Metrics
	log     *slog.Logger
}

// New builds the proxy.
func New(opts Options, engine *waf.Engine) *Server {
	if opts.MaxBody <= 0 {
		opts.MaxBody = 1 << 20
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	s := &Server{opts: opts, engine: engine, Metrics: newMetrics(), log: opts.Logger}
	if opts.RateLimit > 0 {
		s.limiter = NewRateLimiter(opts.RateLimit, opts.Burst)
	}

	rp := httputil.NewSingleHostReverseProxy(opts.Upstream)
	rp.Transport = &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:        1024,
		MaxIdleConnsPerHost: 1024,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   false,
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		s.Metrics.upstreamErr.Add(1)
		s.log.Warn("upstream error", "err", err.Error(), "path", r.URL.Path)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "upstream unavailable"})
	}
	s.proxy = rp
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := newID()
	w.Header().Set("X-Request-ID", id)
	ip := s.clientIP(r)

	if s.limiter != nil && !s.limiter.Allow(ip) {
		s.Metrics.rateLimited.Add(1)
		s.Metrics.record(Event{Time: time.Now(), ID: id, IP: ip, Method: r.Method, Path: truncate(r.URL.RequestURI(), 200), Action: "rate-limited", Message: "per-IP rate limit exceeded"})
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded", "request_id": id})
		return
	}

	var body []byte
	if r.Body != nil && r.Body != http.NoBody {
		b, err := io.ReadAll(io.LimitReader(r.Body, s.opts.MaxBody+1))
		r.Body.Close()
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "could not read body", "request_id": id})
			return
		}
		if int64(len(b)) > s.opts.MaxBody {
			s.Metrics.tooLarge.Add(1)
			s.Metrics.record(Event{Time: time.Now(), ID: id, IP: ip, Method: r.Method, Path: truncate(r.URL.RequestURI(), 200), Action: "too-large", Message: "request body over limit"})
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body too large", "request_id": id})
			return
		}
		body = b
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r.TransferEncoding = nil
	}

	start := time.Now()
	res := s.engine.Inspect(waf.Extract(r, body))
	took := time.Since(start)
	s.Metrics.observe(res, took)

	block := res.Blocked && !s.opts.Monitor
	action := "allowed"
	switch {
	case block:
		action = "blocked"
		s.Metrics.blocked.Add(1)
	case len(res.Findings) > 0:
		action = "flagged"
		s.Metrics.flagged.Add(1)
	}

	if len(res.Findings) > 0 || s.opts.LogAll {
		s.logRequest(id, ip, r, res, action, took)
	}
	ev := Event{
		Time: time.Now(), ID: id, IP: ip, Method: r.Method, Path: truncate(r.URL.RequestURI(), 200),
		Score: res.Score, Action: action, InspectUS: took.Microseconds(),
	}
	if len(res.Findings) > 0 {
		ev.Categories = res.Categories()
		top := res.Findings[0]
		for _, f := range res.Findings {
			if f.Score > top.Score {
				top = f
			}
			if len(ev.Findings) < 12 {
				ev.Findings = append(ev.Findings, EventFinding{
					Rule: f.RuleID, Category: f.Category, Location: f.Location, Name: f.Name, Message: f.Message, Score: f.Score,
				})
			}
		}
		ev.Message = top.Message
	}
	s.Metrics.record(ev)

	if block {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error":      "request blocked by sentinel-waf",
			"request_id": id,
		})
		return
	}

	r.Header.Set("X-Request-ID", id)
	if res.Score > 0 {
		r.Header.Set("X-WAF-Score", strconv.Itoa(res.Score))
	}
	s.proxy.ServeHTTP(w, r)
}

func (s *Server) logRequest(id, ip string, r *http.Request, res waf.Result, action string, took time.Duration) {
	type lf struct {
		Rule int    `json:"rule"`
		Cat  string `json:"cat"`
		Loc  string `json:"loc"`
		Name string `json:"name,omitempty"`
	}
	fs := make([]lf, 0, len(res.Findings))
	for _, f := range res.Findings {
		fs = append(fs, lf{f.RuleID, f.Category, f.Location, f.Name})
	}
	s.log.Info("request",
		"id", id, "ip", ip, "method", r.Method, "uri", truncate(r.URL.RequestURI(), 512),
		"action", action, "score", res.Score, "inspect_us", took.Microseconds(), "findings", fs)
}

func (s *Server) clientIP(r *http.Request) string {
	if s.opts.TrustXFF {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			return strings.TrimSpace(first)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

//go:embed dashboard.html
var dashboardHTML []byte

// AdminHandler serves the dashboard, stats and Prometheus metrics. Bind it to
// localhost only.
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(dashboardHTML)
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		since, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
		secs, _ := strconv.Atoi(r.URL.Query().Get("window"))
		st := s.Metrics.snapshot(since, secs)
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, map[string]any{
			"stats": st, "mode": map[bool]string{true: "monitor", false: "block"}[s.opts.Monitor],
			"threshold": s.engine.Config().Threshold, "paranoia": s.engine.Config().Paranoia,
			"rules": s.engine.RuleCount(), "upstream": s.opts.Upstream.String(),
		})
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		s.Metrics.writePrometheus(w)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func newID() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
