//go:build linux

package poolserver
import("encoding/binary";"os";"path/filepath";"testing")
func TestCredentialACLExactServiceReader(t *testing.T){
 uid:=uint32(1234);acl:=make([]byte,44);binary.LittleEndian.PutUint32(acl,2)
 tags:=[]uint16{1,2,4,16,32};perms:=[]uint16{4,4,0,4,0}
 for i,tag:=range tags{p:=4+8*i;binary.LittleEndian.PutUint16(acl[p:],tag);binary.LittleEndian.PutUint16(acl[p+2:],perms[i]);id:=^uint32(0);if tag==2{id=uid};binary.LittleEndian.PutUint32(acl[p+4:],id)}
 if !credentialACL(acl,uid){t.Fatal("systemd exact service ACL refused")}
 for _,offset:=range []int{0,6,16,22,30,38}{bad:=append([]byte{},acl...);bad[offset]^=1;if credentialACL(bad,uid){t.Fatalf("modified ACL accepted at%d",offset)}}
 if credentialACL(acl,uid+1)||credentialACL(append(acl,make([]byte,8)...),uid){t.Fatal("extra or other service reader accepted")}
}
func TestPrivateFileRejectsGenericGroupReadAndSymlinks(t *testing.T){
 dir:=t.TempDir();path:=filepath.Join(dir,"config");if e:=os.WriteFile(path,[]byte("test"),0600);e!=nil{t.Fatal(e)}
 f,e:=openPrivateFile(path);if e!=nil{t.Fatal(e)};f.Close();if e=os.Chmod(path,0440);e!=nil{t.Fatal(e)};t.Setenv("CREDENTIALS_DIRECTORY",dir);if f,e=openPrivateFile(path);e==nil{f.Close();t.Fatal("generic groupread accepted")}
 if e=os.Chmod(path,0600);e!=nil{t.Fatal(e)};link:=filepath.Join(dir,"link");if e=os.Symlink(path,link);e!=nil{t.Fatal(e)};if f,e=openPrivateFile(link);e==nil{f.Close();t.Fatal("symlink accepted")}
}
