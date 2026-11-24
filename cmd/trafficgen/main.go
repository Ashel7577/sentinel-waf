// Command trafficgen replays a realistic mix of benign and malicious requests
// from the evaluation corpora against a running WAF, spread over many fake
// client IPs (sent as X-Forwarded-For; run the WAF with -trust-xff to see
// them). It exists to drive demos, the dashboard and load tests.
//
// Only point it at a WAF you run yourself.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

func main() {
	target := flag.String("url", "http://127.0.0.1:8080", "WAF base URL")
	rps := flag.Float64("rps", 25, "requests per second")
	attackRatio := flag.Float64("attacks", 0.3, "fraction of requests that are attacks (0-1)")
	dirs := flag.String("corpus", "eval/corpus", "comma-separated corpus dirs")
	attackers := flag.Int("attackers", 14, "number of distinct attacker IPs")
	dur := flag.Duration("duration", 0, "stop after this long (0 = run until Ctrl+C)")
	flag.Parse()

	attacks, benign := load(*dirs)
	if len(attacks) == 0 || len(benign) == 0 {
		fmt.Fprintln(os.Stderr, "corpus not found; run from the repo root or pass -corpus")
		os.Exit(1)
	}
	base := strings.TrimRight(*target, "/")
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	attackerIPs := make([]string, *attackers)
	for i := range attackerIPs {
		attackerIPs[i] = fmt.Sprintf("%d.%d.%d.%d", 23+rnd.Intn(180), rnd.Intn(256), rnd.Intn(256), 1+rnd.Intn(254))
	}
	paths := []string{"/", "/products", "/api/cart", "/search", "/account", "/static/app.js", "/api/orders", "/blog/2024/launch"}
	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
		"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 64}}
	var sent, blocked, ok atomic.Int64

	go func() {
		for range time.Tick(5 * time.Second) {
			fmt.Printf("sent %d · blocked %d · passed %d\n", sent.Load(), blocked.Load(), ok.Load())
		}
	}()

	interval := time.Duration(float64(time.Second) / *rps)
	tick := time.NewTicker(interval)
	defer tick.Stop()
	var stop <-chan time.Time
	if *dur > 0 {
		stop = time.After(*dur)
	}
	for {
		select {
		case <-stop:
			fmt.Printf("done: sent %d · blocked %d · passed %d\n", sent.Load(), blocked.Load(), ok.Load())
			return
		case <-tick.C:
		}
		var r *http.Request
		ip := fmt.Sprintf("10.%d.%d.%d", rnd.Intn(4), rnd.Intn(256), 1+rnd.Intn(254)) // benign users
		if rnd.Float64() < *attackRatio {
			cat := pick(rnd, keys(attacks))
			r = build(rnd, base, pick(rnd, attacks[cat]), rnd.Intn(6))
			ip = attackerIPs[int(rnd.ExpFloat64()*3)%len(attackerIPs)] // a few noisy attackers dominate
			if rnd.Float64() < 0.05 {
				r.Header.Set("User-Agent", pick(rnd, []string{"sqlmap/1.7.11#stable (https://sqlmap.org)", "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)", "Mozilla/5.00 (Nikto/2.5.0)"}))
			}
		} else if rnd.Float64() < 0.5 {
			r = build(rnd, base, pick(rnd, benign), rnd.Intn(3))
		} else {
			r, _ = http.NewRequest("GET", base+pick(rnd, paths), nil)
		}
		if r.Header.Get("User-Agent") == "" {
			r.Header.Set("User-Agent", pick(rnd, uas))
		}
		r.Header.Set("X-Forwarded-For", ip)
		go func(r *http.Request) {
			resp, err := client.Do(r)
			sent.Add(1)
			if err != nil {
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusForbidden {
				blocked.Add(1)
			} else {
				ok.Add(1)
			}
		}(r)
	}
}

// build places a payload in one of several request locations.
func build(rnd *rand.Rand, base, p string, where int) *http.Request {
	var r *http.Request
	switch where {
	case 0:
		r, _ = http.NewRequest("GET", base+"/search?q="+url.QueryEscape(p), nil)
	case 1:
		r, _ = http.NewRequest("POST", base+"/login", strings.NewReader("username="+url.QueryEscape(p)+"&password=hunter2"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	case 2:
		b, _ := json.Marshal(map[string]any{"comment": p, "rating": 1 + rnd.Intn(5)})
		r, _ = http.NewRequest("POST", base+"/api/comments", bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
	case 3:
		r, _ = http.NewRequest("GET", base+"/file?name="+url.QueryEscape(p), nil)
	case 4:
		r, _ = http.NewRequest("GET", base+"/account", nil)
		r.Header.Set("Cookie", "session=8f2a9c; pref="+strings.NewReplacer(";", "", "\n", "", "\r", "").Replace(p))
	default:
		r, _ = http.NewRequest("GET", base+"/api/v1/items", nil)
		r.Header.Set("X-Api-Version", strings.NewReplacer("\n", " ", "\r", " ").Replace(p))
	}
	if r == nil { // payload made an invalid URL; fall back to the query form
		r, _ = http.NewRequest("GET", base+"/search?q="+url.QueryEscape(p), nil)
	}
	return r
}

func pick[T any](rnd *rand.Rand, xs []T) T { return xs[rnd.Intn(len(xs))] }

func keys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func load(dirs string) (map[string][]string, []string) {
	attacks := map[string][]string{}
	var benign []string
	for _, d := range strings.Split(dirs, ",") {
		files, _ := filepath.Glob(filepath.Join(d, "attack", "*.txt"))
		for _, f := range files {
			c := strings.TrimSuffix(filepath.Base(f), ".txt")
			attacks[c] = append(attacks[c], lines(f)...)
		}
		files, _ = filepath.Glob(filepath.Join(d, "benign", "*.txt"))
		for _, f := range files {
			benign = append(benign, lines(f)...)
		}
	}
	return attacks, benign
}

func lines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimRight(sc.Text(), "\r"); strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}
