//go:build windows

package server

import (
	"syscall"
	"unsafe"
)

// On Windows the runtime's monotonic clock can tick as coarsely as ~0.5-1 ms,
// which turns microsecond inspection times into 0 or 1 ms. Use the
// high-resolution performance counter instead so dashboard latency is real.
var (
	k32     = syscall.NewLazyDLL("kernel32.dll")
	qpc     = k32.NewProc("QueryPerformanceCounter")
	qpf     = k32.NewProc("QueryPerformanceFrequency")
	qpcFreq int64
)

func init() {
	qpf.Call(uintptr(unsafe.Pointer(&qpcFreq)))
}

// nanotime returns a high-resolution monotonic timestamp in nanoseconds.
func nanotime() int64 {
	var c int64
	qpc.Call(uintptr(unsafe.Pointer(&c)))
	if qpcFreq <= 0 {
		return 0
	}
	sec := c / qpcFreq
	return sec*1e9 + (c%qpcFreq)*1e9/qpcFreq
}
