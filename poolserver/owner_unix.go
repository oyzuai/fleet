//go:build unix

package poolserver

import (
 "errors"
 "os"
 "syscall"
)
func checkRootOwner(info os.FileInfo) error { s,ok:=info.Sys().(*syscall.Stat_t); if !ok || (s.Uid!=0&&s.Uid!=uint32(os.Geteuid())) {return errors.New("configuration and App key must be owned by root or the service user")};return nil }
