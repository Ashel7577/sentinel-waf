package redteam

import (
	"net/url"
	"strconv"
)

func itoa(n int) string { return strconv.Itoa(n) }

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func urlq(s string) string { return url.QueryEscape(s) }

func urlDecode(s string) string {
	if d, err := url.QueryUnescape(s); err == nil {
		return d
	}
	return s
}

// Tune evaluates detection vs false positives across operating points and
// marks the recommended one: the highest detection whose false-positive rate
// stays within fpBudget; if none qualifies, the point with the lowest FP rate.
// verdictAt(paranoia) returns a Target configured at that paranoia level.
func Tune(points []struct{ Paranoia, Threshold int }, mk func(paranoia, threshold int) Target, benign []string, fpBudget float64) []TunePoint {
	ss := seeds()
	pls := placements()
	var out []TunePoint
	bestIdx, bestScore := -1, -1.0
	fallbackIdx, fallbackFP := -1, 2.0
	for _, pt := range points {
		tg := mk(pt.Paranoia, pt.Threshold)
		landed, blocked := 0, 0
		for _, s := range ss {
			for _, pl := range pls {
				req := pl.Build(s.Payload)
				if marks(tg.Lands(req), s.Marker) {
					landed++
					if tg.Inspect(req).Blocked {
						blocked++
					}
				}
			}
		}
		fp, nb := 0, 0
		for _, b := range benign {
			nb++
			if tg.Inspect(Request{"GET", "/search?q=" + urlq(b), nil, nil}).Blocked {
				fp++
			}
		}
		det := rate(blocked, landed)
		fpr := rate(fp, nb)
		out = append(out, TunePoint{Paranoia: pt.Paranoia, Threshold: pt.Threshold, DetectionRate: det, FPRate: fpr})
		if fpr <= fpBudget && det > bestScore {
			bestScore, bestIdx = det, len(out)-1
		}
		if fpr < fallbackFP {
			fallbackFP, fallbackIdx = fpr, len(out)-1
		}
	}
	pick := bestIdx
	if pick < 0 {
		pick = fallbackIdx
	}
	if pick >= 0 {
		out[pick].Recommended = true
	}
	return out
}

func rate(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}
