//go:build !windows

// Package hrclock is a high-resolution monotonic clock.
package hrclock

import "time"

var epoch = time.Now()

// Now returns a monotonic timestamp in nanoseconds.
func Now() int64 { return int64(time.Since(epoch)) }
