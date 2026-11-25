// Command waf runs Sentinel WAF as a reverse proxy in front of an upstream app.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Ashel7577/sentinel-waf/internal/evidence"
	"github.com/Ashel7577/sentinel-waf/internal/server"
	"github.com/Ashel7577/sentinel-waf/internal/waf"
)

func main() {
	listen := flag.String("listen", ":8080", "proxy listen address")
	admin := flag.String("admin", "127.0.0.1:9090", "admin/dashboard listen address (keep on localhost)")
	upstream := flag.String("upstream", "http://127.0.0.1:8000", "upstream application URL")
	monitor := flag.Bool("monitor", false, "shadow mode: log detections but never block")
	threshold := flag.Int("threshold", 5, "anomaly score that blocks a request")
	paranoia := flag.Int("paranoia", 1, "paranoia level 1-4 (higher = stricter, more false positives)")
	rulesPath := flag.String("rules", "", "JSON rule file (hot-reloaded on change); default: embedded rules")
	maxBody := flag.Int64("max-body", 1<<20, "maximum request body in bytes")
	rate := flag.Float64("rate", 0, "per-IP requests/second limit (0 = off)")
	burst := flag.Int("burst", 0, "per-IP burst size for -rate")
	trustXFF := flag.Bool("trust-xff", false, "use X-Forwarded-For for client IP (only behind a trusted proxy)")
	logPath := flag.String("log", "", "JSON log file (default stdout)")
	logAll := flag.Bool("log-all", false, "log every request, not only ones with findings")
	evPath := flag.String("evidence", "", "tamper-evident evidence file (JSONL hash chain) for blocked/flagged requests; enables /report")
	flag.Parse()

	up, err := url.Parse(*upstream)
	if err != nil || up.Scheme == "" || up.Host == "" {
		fatal("invalid -upstream %q", *upstream)
	}

	var logOut io.Writer = os.Stdout
	if *logPath != "" {
		f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			fatal("open log: %v", err)
		}
		defer f.Close()
		logOut = f
	}
	logger := slog.New(slog.NewJSONHandler(logOut, nil))

	rs := waf.DefaultRules()
	if *rulesPath != "" {
		rs = mustLoadRules(*rulesPath)
	}
	engine := waf.NewEngine(waf.Config{Threshold: *threshold, Paranoia: *paranoia}, rs)
	if *rulesPath != "" {
		go watchRules(*rulesPath, engine, logger)
	}

	var vault *evidence.Vault
	if *evPath != "" {
		v, err := evidence.Open(*evPath)
		if err != nil {
			fatal("evidence: %v", err)
		}
		defer v.Close()
		vault = v
	}

	srv := server.New(server.Options{
		Upstream: up, Monitor: *monitor, MaxBody: *maxBody, RateLimit: *rate, Burst: *burst,
		TrustXFF: *trustXFF, LogAll: *logAll, Logger: logger, Evidence: vault, EvidencePath: *evPath,
	}, engine)

	proxy := &http.Server{
		Addr: *listen, Handler: srv,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second,
		MaxHeaderBytes: 64 << 10,
	}
	adminSrv := &http.Server{Addr: *admin, Handler: srv.AdminHandler(), ReadHeaderTimeout: 5 * time.Second}

	mode := "block"
	if *monitor {
		mode = "monitor"
	}
	fmt.Fprintf(os.Stderr, "sentinel-waf  proxy %s -> %s  |  dashboard http://%s  |  mode=%s threshold=%d paranoia=%d rules=%d\n",
		*listen, up, *admin, mode, *threshold, *paranoia, engine.RuleCount())

	go func() {
		if err := adminSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fatal("admin: %v", err)
		}
	}()
	go func() {
		if err := proxy.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fatal("proxy: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	proxy.Shutdown(ctx)
	adminSrv.Shutdown(ctx)
}

func mustLoadRules(path string) *waf.RuleSet {
	data, err := os.ReadFile(path)
	if err != nil {
		fatal("read rules: %v", err)
	}
	rs, err := waf.ParseRules(data)
	if err != nil {
		fatal("parse rules: %v", err)
	}
	return rs
}

// watchRules polls the rule file and swaps it in atomically when it changes.
// A broken edit is rejected and the previous rules stay active.
func watchRules(path string, e *waf.Engine, log *slog.Logger) {
	var last time.Time
	if st, err := os.Stat(path); err == nil {
		last = st.ModTime()
	}
	for range time.Tick(2 * time.Second) {
		st, err := os.Stat(path)
		if err != nil || !st.ModTime().After(last) {
			continue
		}
		last = st.ModTime()
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		rs, err := waf.ParseRules(data)
		if err != nil {
			log.Error("rule reload rejected, keeping previous rules", "err", err.Error())
			continue
		}
		e.SetRules(rs)
		log.Info("rules reloaded", "count", len(rs.Rules))
	}
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "sentinel-waf: "+format+"\n", a...)
	os.Exit(1)
}
