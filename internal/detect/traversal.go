package detect

import (
	"regexp"
	"strings"
)

var (
	reDotDot    = regexp.MustCompile(`\.\.;?[/\\]|[/\\]\.\.`)
	reSensitive = regexp.MustCompile(`(?:etc[/\\](?:passwd|shadow|group|hosts|issue|sudoers|crontab)|proc[/\\]self[/\\]|win\.ini|boot\.ini|system32|\.ssh[/\\]|id_rsa|web\.config|web-inf|meta-inf|wp-config|\.htaccess|\.htpasswd|\.env\b|\.git[/\\]|\.aws[/\\]|applicationhost\.config)`)
	// Files an attacker reads through LFI: configs, logs, keys, histories.
	reFileish  = regexp.MustCompile(`\.(?:conf|cnf|ini|log|htpasswd|htaccess|rhosts|bash_history|bashrc|profile|pem|key|sqlite3?|bak|swp)\b|(?:access|error)[_.]log|[/\\](?:passwd|shadow|fstab|authorized_keys|known_hosts|environ|cmdline|httpd|nginx|apache2?|samba|mysql|pure-ftpd)\b`)
	reSrcExt   = regexp.MustCompile(`\.(?:asp|aspx|php\d?|jsp|inc|config|properties|ya?ml|xml|json|cfg)\b`)
	reAbsolute = regexp.MustCompile(`^(?:/etc/(?:passwd|shadow|group|hosts|sudoers)|/proc/(?:self|\d+)/|/var/log/|/root/|[a-z]:[\\/](?:windows|winnt|boot\.ini|inetpub)\b)`)
	reAbsStart = regexp.MustCompile(`^(?:/|~/|\\\\|[a-z]:[\\/])`)
	reWrapper  = regexp.MustCompile(`\b(?:php|expect|zip|phar|glob|jar|zlib|compress\.zlib|data|file|rar|ogg|ssh2)://`)
)

// Traversal detects path traversal, local file inclusion and stream wrappers.
// It is safe to run on the request path itself.
func Traversal(s string) []Hit {
	if len(s) < 3 {
		return nil
	}
	var hs hitSet
	if strings.Contains(s, "..") {
		n := len(reDotDot.FindAllStringIndex(s, 8))
		if n >= 1 {
			switch {
			case reSensitive.MatchString(s) || reFileish.MatchString(s) || reSrcExt.MatchString(s):
				hs.add(4001, "traversal", Critical, 1, "path traversal to a sensitive file")
			case n >= 3:
				hs.add(4002, "traversal", Critical, 1, "deep directory traversal")
			case n == 2:
				hs.add(4002, "traversal", Error, 1, "directory traversal")
			}
		}
	}
	if (s[0] == '/' || s[1] == ':') && reAbsolute.MatchString(s) {
		hs.add(4003, "traversal", Critical, 1, "absolute path to a sensitive system location")
	}
	if strings.Contains(s, "://") && reWrapper.MatchString(s) {
		hs.add(4004, "traversal", Critical, 1, "file inclusion stream wrapper")
	}
	return hs.hits
}

// FileAccess flags parameter values that name a sensitive server file
// directly (LFI without "../"). It must not run on the request path, where
// absolute paths are normal.
func FileAccess(s string) []Hit {
	if len(s) < 4 || !strings.ContainsAny(s, `/\`) {
		return nil
	}
	if (strings.Contains(s, "passwd") || strings.Contains(s, "shadow") || strings.Contains(s, ".ini") ||
		strings.Contains(s, "proc") || strings.Contains(s, "id_rsa")) && reSensitive.MatchString(s) {
		return []Hit{{ID: 4006, Category: "traversal", Score: Critical, PL: 1, Msg: "reference to a sensitive system file"}}
	}
	if reAbsStart.MatchString(s) && (reSensitive.MatchString(s) || reFileish.MatchString(s)) {
		return []Hit{{ID: 4006, Category: "traversal", Score: Critical, PL: 1, Msg: "absolute path to a server config/log/key file"}}
	}
	return nil
}

// NullByte inspects the RAW (not normalized) value for NUL bytes, which are
// used to truncate file extensions ("../../etc/passwd%00.png").
func NullByte(raw string) []Hit {
	if strings.Contains(raw, "%00") || strings.IndexByte(raw, 0) >= 0 || strings.Contains(raw, `\x00`) || strings.Contains(raw, `\u0000`) {
		return []Hit{{ID: 4005, Category: "traversal", Score: Warning, PL: 1, Msg: "NUL byte injection"}}
	}
	return nil
}
