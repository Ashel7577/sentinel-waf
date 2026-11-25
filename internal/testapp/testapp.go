// Package testapp is a deliberately permissive demo web application used as
// the upstream behind the WAF in evaluations. It never executes anything: it
// parses each request the way a typical Go handler would and echoes back every
// value it received, so a test harness can tell whether a payload actually
// reached an application parameter (a real bypass) or was dropped on the way
// (a harmless miss). It is safe to run anywhere.
package testapp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Received is the oracle response: the values the application parsed out.
type Received struct {
	Values []string `json:"received"`
}

// Handler returns the demo application.
func Handler() http.Handler {
	type input struct {
		Role, Q, Host, Name, Cmd string
	}
	mux := http.NewServeMux()
	report := func(w http.ResponseWriter, all ...[]string) {
		vals := []string{}
		for _, g := range all {
			for _, v := range g {
				if v != "" {
					vals = append(vals, v)
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Received{Values: vals})
	}
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		report(w, r.URL.Query()["q"], r.URL.Query()["name"])
	})
	mux.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
		report(w, r.URL.Query()["name"])
	})
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		report(w, r.URL.Query()["host"])
	})
	form := func(w http.ResponseWriter, r *http.Request) {
		var vals []string
		_ = r.ParseMultipartForm(8 << 20) // also handles urlencoded via ParseForm
		for _, vs := range r.Form {
			vals = append(vals, vs...)
		}
		if r.MultipartForm != nil {
			for _, fhs := range r.MultipartForm.File {
				for _, fh := range fhs {
					vals = append(vals, fh.Filename)
				}
			}
		}
		report(w, vals)
	}
	mux.HandleFunc("/form", form)
	mux.HandleFunc("/upload", form)
	mux.HandleFunc("/login", form)
	apiJSON := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		var vals []string
		var m map[string]any
		if json.Unmarshal(body, &m) == nil {
			for _, v := range m {
				vals = append(vals, fmt.Sprint(v))
			}
		}
		var in input // Go struct decode: case-insensitive key matching
		if json.Unmarshal(body, &in) == nil {
			vals = append(vals, in.Role, in.Q, in.Host, in.Name, in.Cmd)
		}
		report(w, vals)
	}
	mux.HandleFunc("/api", apiJSON)
	mux.HandleFunc("/api/json", apiJSON)
	mux.HandleFunc("/api/comments", apiJSON)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			report(w, r.URL.Query()["q"])
			return
		}
		apiJSON(w, r)
	})
	return mux
}
