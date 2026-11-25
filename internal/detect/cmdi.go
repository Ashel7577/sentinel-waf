package detect

import (
	"regexp"
	"strings"
)

// OS command injection: a shell separator / substitution followed by a
// command. Commands that are also common English words (cat, find, sleep,
// echo...) are only flagged when they carry shell-like arguments, so
// "cats & dogs" or "eat; sleep; repeat" are left alone.
//
// Performance: the value is scanned once for separator bytes; after each one
// the next shell word is extracted and looked up in a table. No regex runs in
// the common path.

func set(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

var (
	// Unambiguous system commands.
	strongCmds = set("whoami", "uname", "wget", "curl", "ncat", "netcat", "bash", "zsh", "ksh", "dash",
		"python", "perl", "ruby", "lua", "chmod", "chown", "chgrp", "nslookup", "powershell", "pwsh",
		"cmd", "certutil", "bitsadmin", "ifconfig", "ipconfig", "netstat", "systeminfo", "tasklist",
		"tftp", "telnet", "xxd", "printenv", "hostname", "mkfifo", "crontab", "useradd", "passwd",
		"sudo", "nohup", "socat", "rundll32", "regsvr32", "mshta", "wmic", "cscript", "wscript")
	// Commands that are also English words: need shell-like arguments.
	weakCmds = set("cat", "tac", "ls", "dir", "id", "rm", "cp", "mv", "sh", "nc", "ping", "sleep", "echo",
		"printf", "find", "head", "tail", "more", "less", "dig", "host", "timeout", "php", "node",
		"base64", "type", "net", "kill", "ps", "env", "awk", "sed", "grep", "touch", "wc", "od", "nl")
	// Commands that are dangerous even without arguments ("; id", "| whoami").
	bareCmds = set("cat", "ls", "id", "whoami", "pwd", "ps", "env", "set", "ver", "uname", "ifconfig",
		"ipconfig", "hostname", "dir")
	ctlCmds     = set("sleep", "echo", "cat", "id", "ls", "ping", "whoami", "printf")
	binPrefixes = []string{"/usr/local/sbin/", "/usr/local/bin/", "/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/"}
)

var (
	reBinPath = regexp.MustCompile(`(?:^|[\s;&|` + "`" + `(=])/(?:usr/)?(?:local/)?s?bin/[a-z]`)
	reIFS     = regexp.MustCompile(`\$\{?ifs\}?|\$\{(?:path|home|shell):`)
	// nc/ncat -e runs a program on connect; host and port usually come first
	// ("nc attacker 4444 -e /bin/sh"), so allow arguments before the flag.
	reRevShell = regexp.MustCompile(`(?i)/dev/(?:tcp|udp)/|\bnc(?:at)?\b[^;|&\n]{0,80}?\s-[a-z]*e\b|\bbash\s+-i\b|\bsh\s+-i\b|\bmkfifo\b|\bsocat\s+(?:tcp|exec)`)
	reSubst    = regexp.MustCompile(`\$\([^)]{1,200}\)|` + "`" + `[^` + "`" + `]{1,200}` + "`")
	reArith    = regexp.MustCompile(`\$\(\(\s*[\w$]+\s*[-+*/%^]\s*[\w$]+\s*\)\)|\$\[\s*\d+\s*[-+*/]\s*\d+\s*\]`)
	reIfTest   = regexp.MustCompile(`\bif\s+\[\s+[^\]]*\s-(?:ne|eq|gt|lt|ge|le)\s|\$\{#\w+\}`)
)

// shellWord returns the first command word of tail (after blanks, an
// optional backslash and an optional /bin-style directory) and what follows.
func shellWord(tail string) (string, string) {
	i := 0
	for i < len(tail) && (tail[i] == ' ' || tail[i] == '\t') {
		i++
	}
	t := strings.TrimPrefix(tail[i:], `\`)
	for _, p := range binPrefixes {
		if strings.HasPrefix(t, p) {
			t = t[len(p):]
			break
		}
	}
	j := 0
	for j < len(t) {
		c := t[j]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-' && j > 0 {
			j++
			continue
		}
		break
	}
	w := strings.TrimSuffix(t[:j], ".exe")
	if strings.HasPrefix(w, "python") && strings.Trim(w[6:], "0123456789.") == "" {
		w = "python"
	}
	return w, t[j:]
}

func isArgStart(rest string) bool {
	if rest == "" || (rest[0] != ' ' && rest[0] != '\t') {
		return false
	}
	rest = strings.TrimLeft(rest, " \t")
	return rest != "" && strings.IndexByte(`-/.$'"\0123456789~*{`, rest[0]) >= 0
}

func isCmdEnd(rest string) bool {
	rest = strings.TrimLeft(rest, " \t")
	return rest == "" || strings.IndexByte(";|&`)#\n", rest[0]) >= 0
}

// CmdI analyses a normalized value.
func CmdI(s string) []Hit {
	if len(s) < 2 {
		return nil
	}
	var hs hitSet

	if strings.Contains(s, "bin/") && reBinPath.MatchString(s) {
		hs.add(3005, "cmdi", Error, 1, "absolute path to a system binary")
	}
	if ls := strings.ToLower(s); (strings.Contains(ls, "/dev/") || strings.Contains(ls, "nc") || strings.Contains(ls, "sh -i") ||
		strings.Contains(ls, "mkfifo") || strings.Contains(ls, "socat")) && reRevShell.MatchString(s) {
		hs.add(3004, "cmdi", Critical, 1, "reverse shell pattern")
	}
	if !strings.ContainsAny(s, ";&|`\n$") {
		return hs.hits
	}

	if strings.IndexByte(s, '$') >= 0 {
		if (strings.Contains(s, "$((") || strings.Contains(s, "$[")) && reArith.MatchString(s) {
			hs.add(3007, "cmdi", Critical, 1, "shell arithmetic expansion $((a+b)) (blind injection probe)")
		}
		if (strings.Contains(s, "ifs") || strings.Contains(s, "${")) && reIFS.MatchString(s) {
			hs.add(3003, "cmdi", Critical, 1, "shell variable whitespace evasion ($IFS)")
		}
	}
	if (strings.Contains(s, "if [") || strings.Contains(s, "${#")) && reIfTest.MatchString(s) {
		hs.add(3009, "cmdi", Critical, 1, "injected shell control flow / parameter expansion")
	}
	if (strings.Contains(s, "$(") || strings.IndexByte(s, '`') >= 0) && reSubst.MatchString(s) {
		hs.add(3006, "cmdi", Warning, 2, "shell command substitution")
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		var tail string
		subst := false
		switch c {
		case ';', '|', '`', '\n', '&':
			tail = s[i+1:]
		case '$':
			if i+1 >= len(s) || s[i+1] != '(' {
				continue
			}
			tail, subst = s[i+2:], true
			i++
		default:
			continue
		}
		w, rest := shellWord(tail)
		if w == "" {
			continue
		}
		switch {
		case strongCmds[w]:
			hs.add(3001, "cmdi", Critical, 1, "shell separator followed by system command '"+w+"'")
		case weakCmds[w] && isArgStart(rest):
			hs.add(3002, "cmdi", Critical, 1, "shell separator followed by command '"+w+"' with arguments")
		case bareCmds[w] && (c != '&' || (i > 0 && s[i-1] == '&')) && isCmdEnd(rest):
			// a lone "&" is English ("cats & dogs"); "&&", ";", "|" are not
			hs.add(3002, "cmdi", Critical, 1, "shell separator followed by command '"+w+"'")
		case subst && weakCmds[w]:
			hs.add(3008, "cmdi", Critical, 1, "command substitution $("+w+")")
		case !subst && c != '`' && (w == "then" || w == "else" || w == "do"):
			if w2, _ := shellWord(rest); ctlCmds[w2] {
				hs.add(3009, "cmdi", Critical, 1, "injected shell control flow ("+w+" "+w2+")")
			}
		}
	}
	return hs.hits
}
