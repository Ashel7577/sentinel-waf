package detect

import (
	"strings"

	"github.com/Ashel7577/sentinel-waf/internal/normalize"
)

// SQL injection detection by tokenization rather than keyword regexes.
//
// The input is tokenized as SQL three times: as-is (numeric context, e.g.
// "id=1 OR 1=1"), and as if it were placed inside a single- or double-quoted
// string literal (e.g. "name='<input>'"). Injection means the token stream
// breaks out of that context into SQL structure — a closing quote followed by
// boolean logic, a comment, a UNION SELECT, a stacked statement, etc. Plain
// text such as "O'Reilly and sons" tokenizes as string/bareword noise and is
// not flagged, which keyword-based WAFs struggle with.

type token struct {
	t byte   // token class, see classify
	v string // lower-cased value
}

const maxTokens = 32

// Token classes:
//
//	s string  n number  k keyword  U union  & logic (and/or/xor/&&/||)
//	o operator  f function  c comment  v variable  b bareword
//	; ( ) ,  x other
var sqlKeywords = map[string]byte{
	"union": 'U',
	"and":   '&', "or": '&', "xor": '&',
	"not": 'o', "like": 'o', "is": 'o', "in": 'o', "between": 'o', "regexp": 'o',
	"rlike": 'o', "div": 'o', "mod": 'o', "sounds": 'o',
	"true": 'n', "false": 'n',
	"select": 'k', "from": 'k', "where": 'k', "insert": 'k', "update": 'k',
	"delete": 'k', "drop": 'k', "alter": 'k', "create": 'k', "truncate": 'k',
	"table": 'k', "database": 'k', "into": 'k', "values": 'k', "exec": 'k', "execute": 'k',
	"declare": 'k', "having": 'k', "group": 'k', "order": 'k', "by": 'k',
	"limit": 'k', "offset": 'k', "waitfor": 'k', "delay": 'k', "case": 'k',
	"when": 'k', "then": 'k', "else": 'k', "end": 'k', "null": 'k', "all": 'k',
	"distinct": 'k', "shutdown": 'k', "grant": 'k', "set": 'k', "procedure": 'k',
	"user": 'k',
}

// Functions that are only ever called by an attacker probing or exfiltrating.
var riskyFunctions = map[string]bool{
	"sleep": true, "benchmark": true, "pg_sleep": true, "load_file": true,
	"extractvalue": true, "updatexml": true, "xp_cmdshell": true,
	"sp_executesql": true, "randomblob": true, "dbms_pipe.receive_message": true,
	"utl_inaddr.get_host_address": true, "into_outfile": true, "exp": false,
	"geometrycollection": true, "multipoint": true, "polygon": true,
	"name_const": true, "gtid_subset": true, "json_keys": true,
}

// Common functions used to build blind/error-based payloads.
var sqlFunctions = map[string]bool{
	"version": true, "database": true, "user": true, "current_user": true,
	"system_user": true, "session_user": true, "concat": true, "concat_ws": true,
	"char": true, "chr": true, "ascii": true, "substring": true, "substr": true,
	"mid": true, "ord": true, "hex": true, "unhex": true, "if": true,
	"ifnull": true, "count": true, "group_concat": true, "cast": true,
	"convert": true, "length": true, "md5": true, "sha1": true, "rand": true,
	"floor": true, "schema": true, "left": true, "right": true, "coalesce": true,
	"nullif": true, "iif": true, "lower": true, "upper": true, "sys_context": true,
}

// SQLi analyses a normalized value.
func SQLi(s string) []Hit {
	if len(s) < 2 {
		return nil
	}
	s = normalize.StripSQLComments(s)
	var hs hitSet
	for _, ctx := range [...]byte{0, '\'', '"'} {
		if ctx != 0 && strings.IndexByte(s, ctx) < 0 {
			continue
		}
		toks := tokenize(s, ctx)
		analyze(ctx, toks, &hs)
	}
	return hs.hits
}

func analyze(ctx byte, toks []token, hs *hitSet) {
	fp := make([]byte, len(toks))
	for i, t := range toks {
		fp[i] = t.t
	}

	for i, t := range toks {
		switch t.t {
		case 'U':
			j := i + 1
			for j < len(toks) && (toks[j].v == "all" || toks[j].v == "distinct" || toks[j].t == '(') {
				j++
			}
			if j < len(toks) && toks[j].v == "select" {
				hs.add(1001, "sqli", Critical, 1, "UNION-based injection (UNION SELECT)")
			}
		case 'f':
			if riskyFunctions[t.v] {
				hs.add(1002, "sqli", Critical, 1, "time-based/exfiltration function "+t.v+"()")
			}
		case 'k':
			if t.v == "waitfor" && i+1 < len(toks) && toks[i+1].v == "delay" {
				hs.add(1002, "sqli", Critical, 1, "time-based injection (WAITFOR DELAY)")
			}
			if (t.v == "having" || t.v == "where" || t.v == "when") && tautology(toks, i+1) {
				hs.add(1011, "sqli", Critical, 1, "boolean tautology ("+strings.ToUpper(t.v)+" x=x)")
			}
			if i+1 < len(toks) {
				n := toks[i+1]
				switch t.v {
				case "declare":
					if n.t == 'v' {
						hs.add(1015, "sqli", Critical, 1, "T-SQL variable declaration (DECLARE @var)")
					}
				case "exec", "execute":
					if n.t == 'v' || n.t == 'f' || (n.t == '(' && i+2 < len(toks) && (toks[i+2].t == 'v' || toks[i+2].t == 's')) || strings.HasPrefix(n.v, "xp_") ||
						strings.HasPrefix(n.v, "sp_") || strings.HasPrefix(n.v, "master.") {
						hs.add(1015, "sqli", Critical, 1, "dynamic SQL execution (EXEC "+n.v+")")
					}
				}
			}
			if t.v == "select" {
				for _, u := range toks[i+1:] {
					if u.v == "from" {
						hs.add(1010, "sqli", Warning, 1, "SELECT ... FROM statement")
						if fp[len(fp)-1] == 'c' {
							hs.add(1013, "sqli", Critical, 1, "SELECT ... FROM terminated by a comment")
						}
						break
					}
				}
			}
		case 'b':
			if isSystemTable(t.v) {
				hs.add(1014, "sqli", Error, 1, "reference to database catalog table "+t.v)
			}
		case '&':
			if tautology(toks, i+1) {
				hs.add(1011, "sqli", Critical, 1, "boolean tautology (OR x=x)")
			}
		case ';':
			if stacked(toks, i+1) {
				hs.add(1003, "sqli", Critical, 1, "stacked query (; "+toks[i+1].v+" ...)")
			}
		}
	}

	if len(fp) < 2 {
		return
	}

	if ctx != 0 {
		// fp[0] is the string literal we assumed the input starts inside.
		// Everything after it is what the attacker managed to inject.
		rest := fp[1:]
		for len(rest) > 1 && rest[0] == ')' { // ') OR ('1'='1
			rest = rest[1:]
		}
		idx := len(fp) - len(rest)
		switch rest[0] {
		case '&':
			if injectedCondition(toks, idx) {
				hs.add(1004, "sqli", Critical, 1, "quote break-out followed by boolean logic")
			}
		case 'c':
			// "admin'--", "x' #", "'-- -": the comment ends the statement. Prose
			// such as `"--and when she had` continues with words.
			body := strings.TrimSpace(strings.TrimLeft(toks[idx].v, "-#/*"))
			if len(body) <= 4 {
				hs.add(1005, "sqli", Critical, 1, "quote break-out followed by comment terminator")
			} else {
				hs.add(1005, "sqli", Notice, 1, "quote followed by comment marker")
			}
		case 'k':
			kw := toks[idx].v
			next := token{}
			if idx+1 < len(toks) {
				next = toks[idx+1]
			}
			ok := false
			switch kw {
			case "order", "group":
				ok = next.v == "by"
			case "having":
				ok = next.t == 'n' || next.t == 's' || next.t == '(' || next.t == 'f'
			case "procedure":
				ok = next.v == "analyse"
			case "into":
				ok = next.v == "outfile" || next.v == "dumpfile"
			case "limit":
				ok = next.t == 'n'
			}
			if ok {
				hs.add(1006, "sqli", Critical, 1, "quote break-out followed by "+strings.ToUpper(kw)+" clause")
			}
		case 'U':
			hs.add(1001, "sqli", Critical, 1, "quote break-out followed by UNION")
		}
		return
	}

	// Condition appended to a value without any quote: " or 1=1--",
	// ") or ('a'='a", " or 1 in (select @@version)--".
	{
		i := 0
		for i < len(toks)-1 && toks[i].t == ')' {
			i++
		}
		if toks[i].t == '&' && injectedCondition(toks, i) && strings.ContainsAny(string(fp[i+2:]), "oc") {
			hs.add(1012, "sqli", Critical, 1, "appended boolean condition")
		}
	}

	// Numeric context: 1 OR 1=1, 1 AND SLEEP(5), 1) OR (1=1, 1 ORDER BY 3
	if fp[0] == 'n' {
		rest := fp[1:]
		for len(rest) > 1 && rest[0] == ')' {
			rest = rest[1:]
		}
		if len(rest) >= 2 && rest[0] == '&' {
			switch {
			case strings.IndexByte("svf(", rest[1]) >= 0:
				hs.add(1007, "sqli", Critical, 1, "numeric injection with boolean logic")
			case rest[1] == 'n' && len(rest) >= 3 && strings.IndexByte("oc", rest[2]) >= 0:
				hs.add(1007, "sqli", Critical, 1, "numeric tautology (e.g. 1 OR 1=1)")
			}
		}
		if len(toks) >= 4 && toks[1].v == "order" && toks[2].v == "by" && toks[3].t == 'n' {
			if len(toks) >= 5 && toks[4].t == 'c' { // "1 ORDER BY 10--": terminated, clearly injected
				hs.add(1008, "sqli", Critical, 1, "ORDER BY column enumeration with comment terminator")
			} else {
				hs.add(1008, "sqli", Error, 1, "ORDER BY column enumeration")
			}
		}
	}
}

// injectedCondition reports whether the boolean operator at toks[i] is
// followed by an actual SQL condition rather than English ("and he is ...").
func injectedCondition(toks []token, i int) bool {
	at := func(k int) token {
		if k < len(toks) {
			return toks[k]
		}
		return token{}
	}
	a, b, c := at(i+1), at(i+2), at(i+3)
	switch a.t {
	case 'f', 'v':
		return true
	case 'n', 's':
		return b.t == 0 || strings.IndexByte("oc&);", b.t) >= 0
	case '(':
		return strings.IndexByte("kfnsv(", b.t) >= 0
	case 'b':
		if b.t != 'o' {
			return false
		}
		switch {
		case strings.IndexByte("=<>!", b.v[0]) >= 0:
			return true
		case b.v == "is":
			return c.v == "null" || c.v == "not"
		case b.v == "like" || b.v == "regexp" || b.v == "rlike":
			return c.t == 's'
		case b.v == "in":
			return c.t == '('
		}
	}
	return false
}

// tautology reports whether toks[i:] is "[(]* X op X" with X a repeated
// literal: the always-true condition behind OR 1=1 / OR 'a'='a'.
func tautology(toks []token, i int) bool {
	for i < len(toks) && toks[i].t == '(' {
		i++
	}
	if i+2 >= len(toks) {
		return false
	}
	a, op, b := toks[i], toks[i+1], toks[i+2]
	if op.t != 'o' || (a.t != 'n' && a.t != 's') || a.t != b.t || a.v != b.v {
		return false
	}
	switch op.v {
	case "=", "==", "<=>", ">=", "<=", "like", "is":
		return true
	}
	return false
}

func isSystemTable(v string) bool {
	for _, t := range [...]string{"information_schema", "sysobjects", "syscolumns", "sysdatabases",
		"pg_catalog", "pg_tables", "pg_shadow", "pg_user", "mysql.user", "sqlite_master", "all_tables",
		"user_tables", "sys.tables", "sys.objects", "msysobjects", "dba_users", "all_users"} {
		if strings.Contains(v, t) {
			return true
		}
	}
	return false
}

// stacked reports whether toks[i:] starts a dangerous second statement.
func stacked(toks []token, i int) bool {
	if i >= len(toks) || toks[i].t != 'k' && toks[i].t != 'f' {
		return false
	}
	has := func(kw string) bool {
		for _, t := range toks[i+1:] {
			if t.v == kw {
				return true
			}
		}
		return false
	}
	switch toks[i].v {
	case "exec", "execute", "declare", "shutdown", "waitfor", "xp_cmdshell":
		return true
	case "drop", "truncate", "create", "alter":
		return has("table") || has("database") || has("user") || has("procedure")
	case "delete":
		return has("from")
	case "insert":
		return has("into") || has("values")
	case "update":
		return has("set")
	case "select":
		return has("from") || i+1 < len(toks) && (toks[i+1].t == 'f' || toks[i+1].t == 'n')
	}
	return false
}

func tokenize(s string, quote byte) []token {
	toks := make([]token, 0, 16)
	i := 0
	if quote != 0 {
		j := strings.IndexByte(s, quote)
		if j < 0 {
			return []token{{'s', s}}
		}
		toks = append(toks, token{'s', s[:j]})
		i = j + 1
	}
	for i < len(s) && len(toks) < maxTokens {
		c := s[i]
		switch {
		case c <= ' ':
			i++
		case c == '\'' || c == '"' || c == '`':
			j := i + 1
			for j < len(s) {
				if s[j] == '\\' {
					j += 2
					continue
				}
				if s[j] == c {
					if j+1 < len(s) && s[j+1] == c { // '' escape
						j += 2
						continue
					}
					break
				}
				j++
			}
			end := j
			if end > len(s) {
				end = len(s)
			}
			t := byte('s')
			if c == '`' {
				t = 'b'
			}
			toks = append(toks, token{t, s[i+1 : end]})
			i = j + 1
		case isDigit(c) || (c == '.' && i+1 < len(s) && isDigit(s[i+1])):
			j := i
			for j < len(s) && (isIdent(s[j]) || s[j] == '.') {
				j++
			}
			toks = append(toks, token{'n', s[i:j]})
			i = j
		case c == '-' && i+1 < len(s) && s[i+1] == '-', c == '#':
			toks = append(toks, token{'c', s[i:]})
			i = len(s)
		case c == '/' && i+1 < len(s) && s[i+1] == '*': // unterminated comment (terminated ones were stripped)
			toks = append(toks, token{'c', s[i:]})
			i = len(s)
		case c == ';' || c == '(' || c == ')' || c == ',':
			toks = append(toks, token{c, string(c)})
			i++
		case c == '@':
			j := i + 1
			for j < len(s) && (isIdent(s[j]) || s[j] == '@') {
				j++
			}
			toks = append(toks, token{'v', s[i:j]})
			i = j
		case isIdentStart(c):
			j := i
			for j < len(s) && (isIdent(s[j]) || s[j] == '.') {
				j++
			}
			w := s[i:j]
			i = j
			toks = append(toks, token{classify(w, s, j), w})
		case strings.IndexByte("=<>!|&+-*/%^~", c) >= 0:
			j := i + 1
			for j < len(s) && j-i < 3 && strings.IndexByte("=<>!|&", s[j]) >= 0 {
				j++
			}
			op := s[i:j]
			t := byte('o')
			if op == "&&" || op == "||" {
				t = '&'
			}
			toks = append(toks, token{t, op})
			i = j
		default:
			toks = append(toks, token{'x', string(c)})
			i++
		}
	}
	return toks
}

// classify decides the class of an identifier. Known functions only count as
// functions when called (followed by '(', optionally after whitespace).
func classify(w, s string, next int) byte {
	calledAfter := func() bool {
		for k := next; k < len(s); k++ {
			if s[k] == '(' {
				return true
			}
			if s[k] > ' ' {
				return false
			}
		}
		return false
	}
	if w == "xp_cmdshell" {
		return 'f'
	}
	if (riskyFunctions[w] || sqlFunctions[w]) && calledAfter() {
		return 'f'
	}
	if t, ok := sqlKeywords[w]; ok {
		return t
	}
	return 'b'
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isIdentStart(c byte) bool {
	return c == '_' || c == '$' || (c|0x20 >= 'a' && c|0x20 <= 'z') || c >= 0x80
}
func isIdent(c byte) bool { return isIdentStart(c) || isDigit(c) }
