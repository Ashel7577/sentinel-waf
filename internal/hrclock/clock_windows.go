//go:build windows

// Package hrclock is a high-resolution monotonic clock. On Windows the Go
// runtime clock can tick as coarsely as ~0.5-1 ms, which turns microsecond
// measurements into 0; the performance counter does not.
package hrclock

import (
	"syscall"
	"unsafe"
)

var (
	k32  = syscall.NewLazyDLL("kernel32.dll")
	qpc  = k32.NewProc("QueryPerformanceCounter")
	qpf  = k32.NewProc("QueryPerformanceFrequency")
	freq int64
)

func init() { qpf.Call(uintptr(unsafe.Pointer(&freq))) }

// Now returns a monotonic timestamp in nanoseconds.
func Now() int64 {
	var c int64
	qpc.Call(uintptr(unsafe.Pointer(&c)))
	if freq <= 0 {
		return 0
	}
	return c/freq*1e9 + (c%freq)*1e9/freq
}
