//go:build !windows

package server

import "time"

var epoch = time.Now()

// nanotime returns a high-resolution monotonic timestamp in nanoseconds.
func nanotime() int64 { return int64(time.Since(epoch)) }
