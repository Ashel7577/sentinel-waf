// Package evidence keeps a tamper-evident record of every request Sentinel
// blocked or flagged.
//
// Each record holds the full request as received (method, URI, headers and
// body, base64), SHA-256 digests of the raw request and body, the verdict
// with every finding, and the hash of the previous record. The record's own
// hash covers all of that, so the file is a hash chain: editing, deleting or
// reordering any record breaks verification from that point on. This is the
// chain-of-custody property an incident report needs: anyone holding the
// file can re-check that the evidence was not altered after capture.
package evidence

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Genesis is the previous-hash of the first record.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// MaxBody is how much of a body is preserved (the digest always covers the
// whole body the WAF inspected).
const MaxBody = 64 << 10

// Finding mirrors waf.Finding (kept separate so this package has no deps).
type Finding struct {
	RuleID   int    `json:"rule_id"`
	Category string `json:"category"`
	Message  string `json:"message"`
	Score    int    `json:"score"`
	Location string `json:"location"`
	Name     string `json:"name,omitempty"`
	Sample   string `json:"sample,omitempty"`
}

// Record is one piece of evidence.
type Record struct {
	Seq        int64               `json:"seq"`
	Time       time.Time           `json:"time"`
	RequestID  string              `json:"request_id"`
	ClientIP   string              `json:"client_ip"`
	Method     string              `json:"method"`
	URI        string              `json:"uri"`
	Proto      string              `json:"proto"`
	Host       string              `json:"host"`
	Headers    map[string][]string `json:"headers"`
	BodyB64    string              `json:"body_b64,omitempty"`
	BodyLen    int                 `json:"body_len"`
	BodyTrunc  bool                `json:"body_truncated,omitempty"`
	BodySHA256 string              `json:"body_sha256"`
	RawSHA256  string              `json:"raw_request_sha256"`
	Action     string              `json:"action"` // blocked | flagged
	Score      int                 `json:"score"`
	Threshold  int                 `json:"threshold"`
	Findings   []Finding           `json:"findings"`
	EngineVer  string              `json:"engine_version"`
	PrevHash   string              `json:"prev_hash"`
	Hash       string              `json:"hash"`
}

// Body returns the preserved body bytes.
func (r *Record) Body() []byte {
	b, _ := base64.StdEncoding.DecodeString(r.BodyB64)
	return b
}

// Raw rebuilds the request as an HTTP/1.1 message (header order sorted).
func (r *Record) Raw() []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\n", r.Method, r.URI, r.Host)
	keys := make([]string, 0, len(r.Headers))
	for k := range r.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range r.Headers[k] {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	b.Write(r.Body())
	return b.Bytes()
}

func (r *Record) computeHash() string {
	c := *r
	c.Hash = ""
	j, _ := json.Marshal(c)
	h := sha256.Sum256(append([]byte(r.PrevHash), j...))
	return hex.EncodeToString(h[:])
}

// Vault appends records to a JSONL file. Safe for concurrent use.
type Vault struct {
	mu   sync.Mutex
	f    *os.File
	seq  int64
	prev string
}

// Open opens (or creates) a vault file and resumes its chain. It refuses to
// append to a file whose chain is already broken.
func Open(path string) (*Vault, error) {
	v := &Vault{prev: Genesis}
	if _, err := os.Stat(path); err == nil {
		recs, err := ReadFile(path)
		if err != nil {
			return nil, err
		}
		if rep := Verify(recs); !rep.OK {
			return nil, fmt.Errorf("evidence file %s fails verification at seq %d: %s", path, rep.BadSeq, rep.Problem)
		}
		if n := len(recs); n > 0 {
			v.seq, v.prev = recs[n-1].Seq, recs[n-1].Hash
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	v.f = f
	return v, nil
}

// Close closes the file.
func (v *Vault) Close() error { return v.f.Close() }

// Capture builds a record from a request and appends it.
func (v *Vault) Capture(r *http.Request, body []byte, id, ip, action string, score, threshold int, fs []Finding, engineVer string) (*Record, error) {
	rec := &Record{
		Time: time.Now().UTC(), RequestID: id, ClientIP: ip, Method: r.Method, URI: r.URL.RequestURI(),
		Proto: r.Proto, Host: r.Host, Headers: map[string][]string{}, BodyLen: len(body),
		Action: action, Score: score, Threshold: threshold, Findings: fs, EngineVer: engineVer,
	}
	for k, vs := range r.Header {
		if strings.EqualFold(k, "Cookie") || strings.EqualFold(k, "Authorization") {
			// keep evidence, not secrets: record that they were present and their digest
			for _, x := range vs {
				d := sha256.Sum256([]byte(x))
				rec.Headers[k] = append(rec.Headers[k], "[redacted sha256:"+hex.EncodeToString(d[:8])+"]")
			}
			continue
		}
		rec.Headers[k] = append([]string(nil), vs...)
	}
	keep := body
	if len(keep) > MaxBody {
		keep, rec.BodyTrunc = keep[:MaxBody], true
	}
	rec.BodyB64 = base64.StdEncoding.EncodeToString(keep)
	bd := sha256.Sum256(body)
	rec.BodySHA256 = hex.EncodeToString(bd[:])
	rd := sha256.Sum256(rec.Raw())
	rec.RawSHA256 = hex.EncodeToString(rd[:])
	if rec.Findings == nil {
		rec.Findings = []Finding{}
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	v.seq++
	rec.Seq, rec.PrevHash = v.seq, v.prev
	rec.Hash = rec.computeHash()
	line, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	if _, err := v.f.Write(append(line, '\n')); err != nil {
		return nil, err
	}
	if err := v.f.Sync(); err != nil {
		return nil, err
	}
	v.prev = rec.Hash
	return rec, nil
}

// ReadFile loads every record.
func ReadFile(path string) ([]*Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []*Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for n := 1; sc.Scan(); n++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			return out, fmt.Errorf("line %d: %w", n, err)
		}
		out = append(out, &r)
	}
	return out, sc.Err()
}

// Report is the result of a chain verification.
type Report struct {
	OK       bool   `json:"ok"`
	Records  int    `json:"records"`
	BadSeq   int64  `json:"bad_seq,omitempty"`
	Problem  string `json:"problem,omitempty"`
	HeadHash string `json:"head_hash,omitempty"`
}

// ErrBroken is returned by VerifyFile when the chain does not check out.
var ErrBroken = errors.New("evidence chain broken")

// Verify re-computes every hash and link.
func Verify(recs []*Record) Report {
	prev := Genesis
	for i, r := range recs {
		switch {
		case r.Seq != int64(i+1):
			return Report{Records: len(recs), BadSeq: r.Seq, Problem: fmt.Sprintf("sequence gap: expected %d", i+1)}
		case r.PrevHash != prev:
			return Report{Records: len(recs), BadSeq: r.Seq, Problem: "prev_hash does not match the previous record (record removed, inserted or reordered)"}
		case r.computeHash() != r.Hash:
			return Report{Records: len(recs), BadSeq: r.Seq, Problem: "record content does not match its hash (record edited)"}
		}
		if !r.BodyTrunc {
			d := sha256.Sum256(r.Body())
			if hex.EncodeToString(d[:]) != r.BodySHA256 {
				return Report{Records: len(recs), BadSeq: r.Seq, Problem: "preserved body does not match body_sha256"}
			}
		}
		prev = r.Hash
	}
	return Report{OK: true, Records: len(recs), HeadHash: prev}
}

// VerifyFile reads and verifies a vault file.
func VerifyFile(path string) (Report, error) {
	recs, err := ReadFile(path)
	if err != nil {
		return Report{}, err
	}
	rep := Verify(recs)
	if !rep.OK {
		return rep, ErrBroken
	}
	return rep, nil
}
