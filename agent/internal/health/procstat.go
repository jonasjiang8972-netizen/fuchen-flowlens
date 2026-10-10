package health

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// clockTicks is the kernel's USER_HZ, 100 on every mainstream Linux build.
const clockTicks = 100

// procSample reads this process's cumulative CPU time (in clock ticks) and
// resident memory (bytes) from /proc. It fails on systems without procfs.
func procSample() (cpuTicks uint64, rssBytes uint64, err error) {
	stat, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, 0, err
	}
	cpuTicks, err = parseStatCPU(string(stat))
	if err != nil {
		return 0, 0, err
	}
	statm, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, 0, err
	}
	fields := strings.Fields(string(statm))
	if len(fields) < 2 {
		return 0, 0, fmt.Errorf("unexpected /proc/self/statm: %q", statm)
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	return cpuTicks, pages * uint64(os.Getpagesize()), nil
}

// parseStatCPU returns utime+stime from a /proc/<pid>/stat line. The
// command name (field 2) is parenthesised and may contain spaces, so fields
// are counted after its closing parenthesis.
func parseStatCPU(line string) (uint64, error) {
	i := strings.LastIndexByte(line, ')')
	if i < 0 {
		return 0, fmt.Errorf("unexpected /proc/self/stat")
	}
	fields := strings.Fields(line[i+1:])
	// fields[0] is field 3 (state); utime and stime are fields 14 and 15.
	if len(fields) < 13 {
		return 0, fmt.Errorf("unexpected /proc/self/stat")
	}
	utime, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return 0, err
	}
	stime, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return 0, err
	}
	return utime + stime, nil
}
