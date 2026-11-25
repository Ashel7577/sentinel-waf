package evidence

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func capture(t *testing.T, v *Vault, body string) {
	t.Helper()
	r := httptest.NewRequest("POST", "/login?x=1", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Cookie", "session=secret")
	if _, err := v.Capture(r, []byte(body), "id", "1.2.3.4", "blocked", 5, 5,
		[]Finding{{RuleID: 1001, Category: "sqli", Message: "m", Score: 5}}, "test"); err != nil {
		t.Fatal(err)
	}
}

func TestChainVerifiesAndDetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ev.jsonl")
	v, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{`{"q":"1' or 1=1--"}`, `{"q":"<script>"}`, `{"q":"; id"}`} {
		capture(t, v, b)
	}
	v.Close()
	rep, err := VerifyFile(path)
	if err != nil || !rep.OK || rep.Records != 3 {
		t.Fatalf("clean chain: %+v %v", rep, err)
	}
	recs, _ := ReadFile(path)
	if strings.Contains(strings.Join(recs[0].Headers["Cookie"], ""), "secret") {
		t.Fatal("cookie value stored in evidence")
	}

	// Reopen continues the chain.
	v, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	capture(t, v, `{"q":"x"}`)
	v.Close()
	if rep, err := VerifyFile(path); err != nil || rep.Records != 4 {
		t.Fatalf("resumed chain: %+v %v", rep, err)
	}

	// Edit one byte of record 2.
	data, _ := os.ReadFile(path)
	edited := strings.Replace(string(data), `"seq":2,`, `"seq":2, `, 1)
	edited = strings.Replace(edited, `"score":5,"threshold":5`, `"score":4,"threshold":5`, 2)
	os.WriteFile(path, []byte(edited), 0o600)
	rep, err = VerifyFile(path)
	if err == nil || rep.BadSeq != 1 && rep.BadSeq != 2 {
		t.Fatalf("tampering not detected: %+v", rep)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("Open appended to a broken chain")
	}

	// Delete a record.
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	os.WriteFile(path, []byte(lines[0]+"\n"+lines[2]+"\n"), 0o600)
	if rep, err := VerifyFile(path); err == nil {
		t.Fatalf("deletion not detected: %+v", rep)
	}
}
