package parsediff

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"
)

var bom = []byte("\xef\xbb\xbf")

// jsonReadings reads a JSON body.
//
// Readings:
//   - go: encoding/json token stream. Unlike json.Unmarshal into a map it
//     sees every occurrence of a duplicated key, so both the value a
//     first-wins parser keeps and the value a last-wins parser keeps are
//     inspected.
//   - lenient-json: comments and trailing commas removed (JSON5-style and
//     "relaxed" parsers accept them; strict parsers reject the body), used
//     only when the strict reading fails.
//
// Disagreements reported:
//   - json-dup-key: same key twice in one object with different values.
//   - json-case-dup-key: keys that differ only in case with different values.
//     Go's encoding/json matches struct fields case-insensitively, so for a
//     Go backend {"role":"user","ROLE":"admin"} sets Role to "admin".
//   - json-trailing-data: more than one JSON document in the body; some
//     parsers read the first, some reject, streaming parsers read all.
//   - json-nonstandard: only a lenient parser accepts the body.
//   - json-bom: UTF-8 BOM before the document.
func jsonReadings(a *acc, body []byte) {
	b := bytes.TrimSpace(body)
	if bytes.HasPrefix(b, bom) {
		a.amb("json-bom", Warning, "JSON body starts with a UTF-8 byte-order mark; some parsers reject it, others skip it")
		b = bytes.TrimSpace(b[len(bom):])
	}
	docs, ok := walkJSONDocs(a, b, "go")
	if ok {
		a.reading("go")
	} else {
		lb := relaxJSON(b)
		if d2, ok2 := walkJSONDocs(a, lb, "lenient-json"); ok2 && !bytes.Equal(lb, b) {
			a.reading("lenient-json")
			a.amb("json-nonstandard", Critical,
				"body is not valid JSON but becomes valid once comments / trailing commas are removed; relaxed parsers read fields strict ones never see")
			docs = d2
		} else {
			a.field(Field{Kind: KindRaw, Name: "body", Value: string(body), Reading: "raw"})
		}
	}
	if docs > 1 {
		a.amb("json-trailing-data", Critical, "body holds "+strconv.Itoa(docs)+" JSON documents; parsers disagree on which one counts")
	}
}

// walkJSONDocs walks every top-level document. It returns how many were read
// and whether the stream was valid JSON up to EOF.
func walkJSONDocs(a *acc, b []byte, reading string) (int, bool) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	docs := 0
	for {
		err := walkJSON(a, dec, b, "$", 0, reading)
		if err == io.EOF {
			return docs, docs > 0
		}
		if err != nil {
			return docs, false
		}
		docs++
		if docs > 16 {
			return docs, true
		}
	}
}

func walkJSON(a *acc, dec *json.Decoder, src []byte, path string, depth int, reading string) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if depth > maxDepth {
		return skipJSON(dec, tok)
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			vals := map[string]string{}
			lower := map[string]string{}
			lowerName := map[string]string{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return err
				}
				key, _ := kt.(string)
				a.field(Field{Kind: KindJSON, Name: "json", Value: key, Key: true, Reading: reading})
				start := dec.InputOffset()
				if err := walkJSON(a, dec, src, path+"."+key, depth+1, reading); err != nil {
					return err
				}
				fp := fingerprint(src, start, dec.InputOffset())
				if prev, dup := vals[key]; dup && prev != fp {
					a.amb("json-dup-key", Critical, "key \""+clip(key)+"\" appears twice with different values; first-wins and last-wins parsers see different data")
				}
				vals[key] = fp
				lk := strings.ToLower(key)
				if prev, dup := lower[lk]; dup && lowerName[lk] != key && prev != fp {
					a.amb("json-case-dup-key", Critical, "keys \""+clip(lowerName[lk])+"\" and \""+clip(key)+"\" differ only in case; Go's encoding/json maps both to the same struct field (last one wins)")
				}
				lower[lk], lowerName[lk] = fp, key
			}
			_, err := dec.Token() // '}'
			return err
		case '[':
			for i := 0; dec.More(); i++ {
				if err := walkJSON(a, dec, src, path+"["+strconv.Itoa(i)+"]", depth+1, reading); err != nil {
					return err
				}
			}
			_, err := dec.Token() // ']'
			return err
		}
	case string:
		a.field(Field{Kind: KindJSON, Name: path, Value: t, Reading: reading})
	}
	return nil
}

func skipJSON(dec *json.Decoder, tok json.Token) error {
	d, ok := tok.(json.Delim)
	if !ok || (d != '{' && d != '[') {
		return nil
	}
	for n := 1; n > 0; {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := t.(json.Delim); ok {
			if d == '{' || d == '[' {
				n++
			} else {
				n--
			}
		}
	}
	return nil
}

// fingerprint is the raw text of a value (the decoder offset sits after the
// key, so the slice starts with ':').
func fingerprint(src []byte, start, end int64) string {
	if start < 0 || end > int64(len(src)) || start > end {
		return ""
	}
	return strings.TrimLeft(strings.TrimSpace(string(src[start:end])), ": \t\r\n")
}

func clip(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}

// relaxJSON removes // and /* */ comments and trailing commas outside strings.
func relaxJSON(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			out = append(out, c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			i++
		case c == ',':
			j := i + 1
			for j < len(b) && (b[j] == ' ' || b[j] == '\t' || b[j] == '\r' || b[j] == '\n') {
				j++
			}
			if j < len(b) && (b[j] == '}' || b[j] == ']') {
				continue // trailing comma
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out
}
