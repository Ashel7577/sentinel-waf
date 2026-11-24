// Command target is a stand-in "vulnerable" web app used as the WAF's
// upstream in tests and benchmarks. It SIMULATES dangerous sinks — it shows the
// SQL query / shell command / file path it *would* have used — but never runs
// a query, a command or reads a file, so it is safe to run on any machine.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:8000", "listen address")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		reply(w, map[string]string{"query": q, "would_execute_sql": "SELECT * FROM products WHERE name LIKE '%" + q + "%'"})
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		u := r.Form.Get("username")
		reply(w, map[string]string{"would_execute_sql": "SELECT * FROM users WHERE name='" + u + "' AND pw='" + r.Form.Get("password") + "'"})
	})
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]string{"would_run": "ping -c 1 " + r.URL.Query().Get("host")})
	})
	mux.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]string{"would_read": "/var/www/files/" + r.URL.Query().Get("name")})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		reply(w, map[string]any{"method": r.Method, "uri": r.RequestURI, "body_bytes": len(body), "waf_score": r.Header.Get("X-WAF-Score")})
	})

	fmt.Printf("target app (simulated sinks, executes nothing) on http://%s\n", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
