//go:build !linux

package poolserver
import("errors";"os")
func openPrivateFile(path string)(*os.File,error){f,e:=os.Open(path);if e!=nil{return nil,e};i,e:=f.Stat();if e==nil{e=checkRootOwner(i)};if e==nil&&(!i.Mode().IsRegular()||(i.Mode().Perm()!=0400&&i.Mode().Perm()!=0600)){e=errors.New("expected a private regular0400or0600 file")};if e!=nil{f.Close();return nil,e};return f,nil}
