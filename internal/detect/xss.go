package detect

import (
	"regexp"
	"strings"

	"github.com/Ashel7577/sentinel-waf/internal/normalize"
)

// XSS detection looks for the things a browser will actually execute: script
// elements, event-handler attributes inside a tag, attribute break-outs, script
// URL schemes and dangerous embedding elements. Mentioning "onclick" or
// "javascript" in plain text is not flagged.

const eventNames = `on(?:load|error|click|dblclick|auxclick|contextmenu|mouse[a-z]*|pointer[a-z]*|focus[a-z]*|blur|key[a-z]+|submit|change|input|toggle|begin|end|start|finish|animation[a-z]+|transition[a-z]+|touch[a-z]+|drag[a-z]*|drop|copy|cut|paste|wheel|scroll|resize|unload|beforeunload|hashchange|message|pageshow|pagehide|popstate|show|select|play[a-z]*|pause|ended|canplay[a-z]*|loadstart|loadeddata|progress|abort|search|invalid|reset|afterprint|beforeprint|readystatechange|cuechange|formdata|securitypolicyviolation|volumechange|seeked|seeking|waiting|timeupdate|durationchange|ratechange|stalled|suspend|emptied|loadedmetadata|offline|online|storage|bounce)`

var (
	reScriptTag = regexp.MustCompile(`<\s*/?\s*script\b`)
	// [^<]* rather than [^>]*: a quoted ">" inside an attribute (<x 1=">" onx=1)
	// must not end the tag for our purposes.
	reEventInTag  = regexp.MustCompile(`<[a-z!][^<]*?[\s/"'` + "`" + `]on[a-z]{3,}\s*=`)
	reBreakout    = regexp.MustCompile(`["'` + "`" + `](?:[^<>]{0,80}?[\s/"'])?` + eventNames + `\s*=`)
	reJSBreakout  = regexp.MustCompile(`["'` + "`" + `]\s*\)?\s*[-+*/%|&^,;]\s*(?:alert|prompt|confirm|eval|fetch|import|settimeout|top\s*\[|window\s*\[|self\s*\[|parent\s*\[|document\s*\.|location\s*=)`)
	reDangerTag   = regexp.MustCompile(`<\s*(?:iframe|frame|frameset|object|embed|applet|base|meta|isindex|portal)\b`)
	reDangerTagAt = regexp.MustCompile(`<\s*(?:iframe|frame|frameset|object|embed|applet|base|meta|isindex|portal)\b[^>]*?\b(?:src|data|href|code|codebase|content|type|action|srcdoc)\s*=`)
	reSVGMath     = regexp.MustCompile(`<\s*(?:svg|math|xss|template|noscript|style)\b`)
	reDataURI     = regexp.MustCompile(`data:(?:text/html|image/svg\+xml|application/(?:x-)?(?:javascript|ecmascript|xhtml\+xml))`)
	reStyleExec   = regexp.MustCompile(`expression\s*\(|-moz-binding|behavior\s*:|@import`)
	reAttrSink    = regexp.MustCompile(`\b(?:srcdoc|formaction|xlink:href|ping)\s*=`)
	reJSSinks     = regexp.MustCompile(`\b(?:alert|prompt|confirm|eval|settimeout|setinterval|atob|import)\s*\(|fromcharcode|document\.(?:cookie|domain|write|location)|window\.location|\.innerhtml|\bfunction\s*\(`)
	reTemplate    = regexp.MustCompile(`\{\{.*(?:constructor|\$on|\$eval|\$emit).*\}\}`)
	reScheme      = regexp.MustCompile(`(?:java|vb|live|mocha)script:`)
)

// XSS analyses a normalized value.
func XSS(s string) []Hit {
	if len(s) < 4 {
		return nil
	}
	var hs hitSet
	hasLT := strings.IndexByte(s, '<') >= 0
	if hasLT {
		if reScriptTag.MatchString(s) {
			hs.add(2001, "xss", Critical, 1, "<script> element")
		}
		if reEventInTag.MatchString(s) {
			hs.add(2002, "xss", Critical, 1, "event handler attribute inside a tag")
		}
		if reDangerTagAt.MatchString(s) {
			hs.add(2003, "xss", Critical, 1, "embedding element loading external content (iframe/object/embed/base/meta)")
		} else if reDangerTag.MatchString(s) {
			hs.add(2003, "xss", Error, 1, "dangerous embedding element (iframe/object/embed/base/meta)")
		}
		if reSVGMath.MatchString(s) {
			hs.add(2004, "xss", Notice, 2, "SVG/MathML/template element")
		}
	}
	if strings.ContainsAny(s, `"'`+"`") {
		if reBreakout.MatchString(s) {
			hs.add(2005, "xss", Critical, 1, "attribute break-out into event handler")
		}
		if reJSBreakout.MatchString(s) {
			hs.add(2012, "xss", Critical, 1, "JavaScript string break-out into code ('-alert(1)-')")
		}
	}
	if strings.IndexByte(s, ':') >= 0 {
		if reScheme.MatchString(normalize.Compact(s)) {
			hs.add(2006, "xss", Critical, 1, "script URL scheme (javascript:/vbscript:)")
		}
		if reDataURI.MatchString(s) {
			hs.add(2007, "xss", Error, 1, "executable data: URI")
		}
	}
	if (strings.Contains(s, "expression") || strings.Contains(s, "binding") ||
		strings.Contains(s, "behavior") || strings.Contains(s, "@import")) && reStyleExec.MatchString(s) {
		hs.add(2008, "xss", Error, 1, "CSS script execution (expression/binding)")
	}
	if strings.IndexByte(s, '=') >= 0 && reAttrSink.MatchString(s) {
		score := Error
		if hasLT {
			score = Critical
		}
		hs.add(2009, "xss", score, 1, "script-capable attribute (srcdoc/formaction/xlink:href)")
	}
	if strings.Contains(s, "{{") && reTemplate.MatchString(s) {
		hs.add(2010, "xss", Critical, 1, "client-side template injection (AngularJS sandbox escape)")
	}
	if hasSinkWord(s) && reJSSinks.MatchString(s) {
		hs.add(2011, "xss", Notice, 1, "JavaScript sink/function call")
	}
	return hs.hits
}

var sinkWords = [...]string{"alert", "prompt", "confirm", "eval", "settimeout", "setinterval",
	"atob", "import", "fromcharcode", "document.", "window.location", ".innerhtml", "function"}

func hasSinkWord(s string) bool {
	for _, w := range sinkWords {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}
