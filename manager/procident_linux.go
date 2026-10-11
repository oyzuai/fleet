package manager

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// processStart is when pid started, in clock ticks since boot, from
// /proc/<pid>/stat.
func processStart(pid int) (string, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if errors.Is(err, os.ErrNotExist) {
		return "", errProcessGone
	}
	if err != nil {
		return "", err
	}
	// The command name is in parentheses and may hold spaces; the fields
	// after it start with the state, and starttime is the 20th of them.
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return "", fmt.Errorf("unreadable /proc/%d/stat", pid)
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 20 {
		return "", fmt.Errorf("unreadable /proc/%d/stat", pid)
	}
	if f[0] == "Z" || f[0] == "X" {
		return "", errProcessGone
	}
	return f[19], nil
}
