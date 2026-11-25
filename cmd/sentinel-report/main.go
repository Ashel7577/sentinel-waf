// Command sentinel-report is the offline side of Sentinel's built-in analyst.
//
//	sentinel-report verify -evidence evidence.jsonl
//	sentinel-report report -evidence evidence.jsonl -out report.html   (or .md)
//
// verify re-computes every SHA-256 link of the evidence chain and exits
// non-zero if any record was edited, removed, inserted or reordered.
// report writes the incident report (technique, how it works, how it was
// stopped, CWE/CAPEC/ATT&CK ids, raw request, hashes, reproduction command).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Ashel7577/sentinel-waf/internal/analyst"
	"github.com/Ashel7577/sentinel-waf/internal/evidence"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	ev := fs.String("evidence", "evidence.jsonl", "evidence file written by sentinel-waf -evidence")
	out := fs.String("out", "", "report file (.md or .html); default stdout (Markdown)")
	last := fs.Int("last", 0, "only the last N incidents (0 = all)")
	title := fs.String("title", "", "report title")
	asJSON := fs.Bool("json", false, "verify: print the result as JSON")
	fs.Parse(os.Args[2:])

	recs, err := evidence.ReadFile(*ev)
	if err != nil {
		fail("read evidence: %v", err)
	}
	chain := evidence.Verify(recs)

	switch cmd {
	case "verify":
		if *asJSON {
			json.NewEncoder(os.Stdout).Encode(chain)
		} else if chain.OK {
			fmt.Printf("OK  %d records, hash chain intact\nhead %s\n", chain.Records, chain.HeadHash)
		} else {
			fmt.Printf("FAILED at record %d: %s\n", chain.BadSeq, chain.Problem)
		}
		if !chain.OK {
			os.Exit(2)
		}
	case "report":
		if *last > 0 && *last < len(recs) {
			recs = recs[len(recs)-*last:]
		}
		md := analyst.Markdown(analyst.Analyse(recs, nil), chain, *title, "")
		data := md
		if strings.HasSuffix(strings.ToLower(*out), ".html") {
			data = analyst.HTML(md)
		}
		if *out == "" {
			fmt.Print(data)
			return
		}
		if err := os.WriteFile(*out, []byte(data), 0o644); err != nil {
			fail("write: %v", err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s (%d incidents, chain %s)\n", *out, len(recs), map[bool]string{true: "verified", false: "BROKEN"}[chain.OK])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: sentinel-report verify|report -evidence file.jsonl [-out report.html] [-last N]")
	os.Exit(2)
}

func fail(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "sentinel-report: "+f+"\n", a...)
	os.Exit(1)
}
