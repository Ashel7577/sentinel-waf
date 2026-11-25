// Package analyst turns Sentinel's findings and evidence into an incident
// report a human can read: what the attacker tried, how that technique
// works, exactly which part of the request gave it away, why it was blocked,
// and how to fix the application behind the WAF.
//
// The built-in analyst is deterministic and offline: every statement in the
// report comes from the evidence record and this knowledge base, so it can
// never invent a detail. An optional LLM narrative (see llm.go) only
// summarises what is already in the report.
package analyst

import "strings"

// Technique describes one attack class.
type Technique struct {
	Name       string
	CWE        string
	CAPEC      string
	ATTACK     string // MITRE ATT&CK technique
	HowItWorks string
	Impact     string
	Fix        string
	Refs       []string
}

const t1190 = "T1190 Exploit Public-Facing Application"

var byCategory = map[string]Technique{
	"sqli": {
		Name: "SQL injection", CWE: "CWE-89", CAPEC: "CAPEC-66", ATTACK: t1190,
		HowItWorks: "The attacker supplies text that closes the string or number the application pastes into a SQL query and appends SQL of their own (a UNION SELECT to read other tables, a tautology to bypass a WHERE clause, a stacked statement, or a time delay to extract data blind).",
		Impact:     "Reading or modifying any data the database account can reach, authentication bypass, and on some databases command execution.",
		Fix:        "Use parameterised queries / prepared statements for every value; never build SQL by string concatenation. Give the database account least privilege.",
		Refs:       []string{"https://owasp.org/www-community/attacks/SQL_Injection", "https://cwe.mitre.org/data/definitions/89.html"},
	},
	"xss": {
		Name: "Cross-site scripting (XSS)", CWE: "CWE-79", CAPEC: "CAPEC-63", ATTACK: t1190,
		HowItWorks: "The attacker injects HTML or JavaScript that the application later writes into a page without encoding it, so the script runs in other users' browsers with the site's privileges.",
		Impact:     "Session theft, actions performed as the victim, phishing inside the trusted site.",
		Fix:        "Context-aware output encoding (HTML, attribute, JavaScript, URL), a strict Content-Security-Policy, and framework auto-escaping that is never disabled.",
		Refs:       []string{"https://owasp.org/www-community/attacks/xss/", "https://cwe.mitre.org/data/definitions/79.html"},
	},
	"cmdi": {
		Name: "OS command injection", CWE: "CWE-78", CAPEC: "CAPEC-88", ATTACK: t1190,
		HowItWorks: "The attacker adds a shell separator (; | && $( ) `) to a value the application passes to a shell, so a second command of their choosing runs on the server.",
		Impact:     "Full remote code execution with the web server's privileges.",
		Fix:        "Never pass user input to a shell. Call programs directly with an argument array (exec without a shell) and validate input against an allow-list.",
		Refs:       []string{"https://owasp.org/www-community/attacks/Command_Injection", "https://cwe.mitre.org/data/definitions/78.html"},
	},
	"traversal": {
		Name: "Path traversal / local file inclusion", CWE: "CWE-22", CAPEC: "CAPEC-126", ATTACK: t1190,
		HowItWorks: "The attacker uses ../ sequences (often encoded), absolute paths or stream wrappers (php://, file://) so a file path built from their input points outside the intended directory.",
		Impact:     "Reading configuration files, source code and credentials; with inclusion, executing code.",
		Fix:        "Resolve the final path and check it stays inside the allowed base directory; map user choices to IDs instead of file names.",
		Refs:       []string{"https://owasp.org/www-community/attacks/Path_Traversal", "https://cwe.mitre.org/data/definitions/22.html"},
	},
	"ssrf": {
		Name: "Server-side request forgery (SSRF)", CWE: "CWE-918", CAPEC: "CAPEC-664", ATTACK: t1190,
		HowItWorks: "The attacker makes the server fetch a URL of their choosing, typically internal addresses or cloud metadata endpoints (169.254.169.254).",
		Impact:     "Access to internal services and cloud credentials.",
		Fix:        "Allow-list destination hosts, block private and link-local ranges after DNS resolution, and use IMDSv2 on cloud hosts.",
		Refs:       []string{"https://cwe.mitre.org/data/definitions/918.html"},
	},
	"ssti": {
		Name: "Server-side template injection", CWE: "CWE-1336", CAPEC: "CAPEC-242", ATTACK: t1190,
		HowItWorks: "The attacker submits template syntax ({{ }}, ${ }, <% %>) that the server renders as a template, reaching the template engine's object model.",
		Impact:     "Usually remote code execution.",
		Fix:        "Never render user input as a template; pass it only as data. Use sandboxed engines.",
		Refs:       []string{"https://cwe.mitre.org/data/definitions/1336.html"},
	},
	"xxe": {
		Name: "XML external entity (XXE)", CWE: "CWE-611", CAPEC: "CAPEC-221", ATTACK: t1190,
		HowItWorks: "The attacker declares an external entity in a DOCTYPE so the XML parser fetches a local file or URL and inlines it.",
		Impact:     "File disclosure, SSRF, denial of service.",
		Fix:        "Disable DTDs and external entities in the XML parser.",
		Refs:       []string{"https://cwe.mitre.org/data/definitions/611.html"},
	},
	"nosqli": {
		Name: "NoSQL injection", CWE: "CWE-943", CAPEC: "CAPEC-676", ATTACK: t1190,
		HowItWorks: "The attacker sends query operators ($ne, $gt, $where) where the application expects a plain value, changing the meaning of a MongoDB-style query.",
		Impact:     "Authentication bypass and data disclosure.",
		Fix:        "Validate types (a string must stay a string), and strip or reject keys starting with $.",
		Refs:       []string{"https://cwe.mitre.org/data/definitions/943.html"},
	},
	"crlf":   {Name: "CRLF / header injection", CWE: "CWE-93", ATTACK: t1190, HowItWorks: "Encoded carriage-return/line-feed characters split a response header so the attacker can add headers or a body.", Impact: "Response splitting, cache poisoning, session fixation.", Fix: "Reject CR and LF in any value written into a header."},
	"ldapi":  {Name: "LDAP injection", CWE: "CWE-90", CAPEC: "CAPEC-136", ATTACK: t1190, HowItWorks: "LDAP filter metacharacters change a directory query.", Impact: "Authentication bypass, directory disclosure.", Fix: "Escape LDAP filter input (RFC 4515) or use parameterised APIs."},
	"xpathi": {Name: "XPath injection", CWE: "CWE-643", CAPEC: "CAPEC-83", ATTACK: t1190, HowItWorks: "Quote break-out changes an XPath query over an XML document.", Impact: "Data disclosure, authentication bypass.", Fix: "Use parameterised XPath (variables) instead of concatenation."},
	"ssi":    {Name: "Server-side include injection", CWE: "CWE-97", CAPEC: "CAPEC-101", ATTACK: t1190, HowItWorks: "<!--#exec --> style directives are injected into pages the server parses for includes.", Impact: "Command execution.", Fix: "Disable SSI or never include user content in SSI-parsed files."},
	"smuggling": {Name: "HTTP request smuggling", CWE: "CWE-444", CAPEC: "CAPEC-33", ATTACK: t1190,
		HowItWorks: "Conflicting message framing (Content-Length vs Transfer-Encoding, malformed chunking) makes the WAF/proxy and the backend disagree on where one request ends, hiding a second request inside the first.",
		Impact:     "WAF bypass, request hijacking, cache poisoning.", Fix: "Normalise framing at the edge, prefer HTTP/2 end to end, reject ambiguous requests.",
		Refs: []string{"https://portswigger.net/research/http1-must-die"}},
	"scanner": {Name: "Automated scanning / reconnaissance", ATTACK: "T1595 Active Scanning", HowItWorks: "A known attack tool or vulnerability scanner identified itself or used a tell-tale probe.", Impact: "Precursor to targeted attacks.", Fix: "Keep the WAF in front; review what the scanner was probing for."},
	"proto":   {Name: "Prototype pollution", CWE: "CWE-1321", ATTACK: t1190, HowItWorks: "__proto__ / constructor.prototype keys in JSON or query strings modify the prototype of every object in a JavaScript backend.", Impact: "Logic bypass, sometimes code execution.", Fix: "Use Object.create(null) maps, freeze prototypes, reject __proto__ keys."},
	"upload":  {Name: "Malicious file upload", CWE: "CWE-434", ATTACK: t1190, HowItWorks: "A file with an executable extension or content (web shell) is uploaded to a location the server will run.", Impact: "Remote code execution.", Fix: "Allow-list extensions and content types, store uploads outside the web root, rename files."},
	"rce":     {Name: "Remote code execution payload", CWE: "CWE-94", ATTACK: t1190, HowItWorks: "A payload targeting a known code-execution flaw (e.g. Log4Shell JNDI lookups, Shellshock function definitions).", Impact: "Full compromise.", Fix: "Patch the vulnerable component; keep the WAF rule as a virtual patch."},
	"parser-differential": {
		Name: "Parser-differential WAF evasion", CWE: "CWE-436 Interpretation Conflict", CAPEC: "", ATTACK: t1190,
		HowItWorks: "Instead of disguising the payload, the attacker disguises the request's structure (duplicate JSON keys, a second multipart boundary, parts after the closing delimiter, conflicting Content-Type headers, an exotic charset). A WAF that parses the body one way inspects different fields than the framework that parses it another way, and the payload travels in the part only the application reads. WAFFLED (ACSAC 2025) found 1,207 such bypasses across five major cloud WAFs.",
		Impact:     "Any injection the WAF would normally block reaches the application uninspected.",
		Fix:        "Make the application reject the ambiguity too: refuse duplicate JSON keys, use a strict multipart parser, accept one Content-Type per endpoint.",
		Refs:       []string{"https://arxiv.org/abs/2503.10846", "https://cwe.mitre.org/data/definitions/436.html"},
	},
}

// Parser-differential sub-techniques: why each one fools some parser.
var parseDiffWhy = map[string]string{
	"json-dup-key":                 "Duplicate JSON keys: Go, Python and JavaScript keep the last value, other parsers keep the first, so a WAF and a backend can read different values for the same key.",
	"json-case-dup-key":            "Keys differing only in case: Go's encoding/json matches struct fields case-insensitively, so \"ROLE\" silently overwrites \"role\" in a Go backend.",
	"json-trailing-data":           "Two JSON documents in one body: a WAF that reads the first document misses fields a streaming backend reads from the second.",
	"json-nonstandard":             "Comments or trailing commas: strict JSON parsers (most WAFs) reject the body and skip inspection, relaxed parsers in the backend accept it.",
	"json-bom":                     "Byte-order mark before JSON: some parsers fail on it (no inspection), others skip it.",
	"multipart-boundary-ambiguous": "Two boundary= parameters: parsers that take the first and parsers that take the last split the body into different parts.",
	"multipart-boundary-prefix":    "Delimiter that only starts with the boundary: prefix-matching and exact-matching parsers see different parts.",
	"multipart-after-close":        "Parts after the closing delimiter: most WAFs stop at the close, several framework parsers keep reading.",
	"multipart-dup-param":          "Two name= parameters in one Content-Disposition: the WAF and the backend file the value under different field names.",
	"multipart-dup-filename":       "Two filename= parameters: the upload name the WAF checks is not the one the backend saves.",
	"multipart-filename-conflict":  "filename and filename* disagree: RFC 6266 parsers use filename*, others use filename, so a traversal hidden in filename* passes a WAF that checks filename.",
	"multipart-lf-line-endings":    "LF-only line endings: strict parsers fail and skip the body, lenient ones parse it.",
	"multipart-unterminated":       "No closing delimiter: some parsers drop the last part, others keep it (CVE-2026-41508 in Coraza).",
	"multipart-parser-disagree":    "Go's mime/multipart and a lenient parser extracted different fields from the same body.",
	"content-type-duplicate":       "Two different Content-Type headers: proxies and frameworks disagree on which one decides how the body is parsed.",
	"content-type-mismatch":        "Body shaped differently from its declared Content-Type: frameworks that sniff or force-parse read a structure the WAF never parsed.",
	"content-type-malformed":       "Content-Type that only lenient parsers accept.",
	"body-charset":                 "Exotic charset (ibm037, utf-16, utf-7): the backend decodes bytes into a payload the WAF only sees as noise.",
	"form-semicolon-separator":     "';' used as a parameter separator: Go ignores those pairs, older Python and Java servers split on them.",
	"query-semicolon-separator":    "';' used as a parameter separator in the query string.",
	"form-bad-escape":              "Malformed percent-escape: Go drops the pair, other parsers keep it literally.",
	"query-bad-escape":             "Malformed percent-escape in the query string.",
	"body-invalid-utf8":            "Invalid UTF-8: parsers repair it differently.",
}

// TechniqueFor returns the technique of a finding category ("rule" categories
// fall back to a generic entry).
func TechniqueFor(category string) Technique {
	if t, ok := byCategory[strings.ToLower(category)]; ok {
		return t
	}
	return Technique{Name: "Suspicious request (" + category + ")", ATTACK: t1190,
		HowItWorks: "A rule-file signature matched.", Impact: "Depends on the signature.", Fix: "Review the matched rule."}
}

// ParseDiffWhy explains one parser-differential code.
func ParseDiffWhy(code string) string {
	if s, ok := parseDiffWhy[code]; ok {
		return s
	}
	return "Parsers disagree on this request's structure."
}
