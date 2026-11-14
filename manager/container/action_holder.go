package container

import (
	"archive/tar"
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"

	"github.com/oyzuai/fleet/runnerclient"
)

const actionHelperLimit = 64 << 20

func (r *ActionRuntime) helper() ([]byte, error) {
	p := r.HelperPath
	if p == "" {
		var err error
		p, err = os.Executable()
		if err != nil {
			return nil, err
		}
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > actionHelperLimit {
		return nil, errors.New("invalid installed action helper size")
	}
	binary, err := elf.NewFile(f)
	if err != nil {
		return nil, err
	}
	if binary.Class != elf.ELFCLASS64 || binary.Machine != elf.EM_X86_64 || binary.Data != elf.ELFDATA2LSB || (binary.Type != elf.ET_EXEC && binary.Type != elf.ET_DYN) || (binary.OSABI != elf.ELFOSABI_NONE && binary.OSABI != elf.ELFOSABI_LINUX) {
		return nil, errors.New("action helper must be static Linux amd64")
	}
	for _, p := range binary.Progs {
		if p.Type == elf.PT_INTERP {
			return nil, errors.New("action helper must be static")
		}
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, actionHelperLimit+1))
	if err != nil || len(data) > actionHelperLimit {
		return nil, errors.New("installed action helper unavailable")
	}
	return data, nil
}

func helperArchive(data []byte) ([]byte, error) {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	if err := tw.WriteHeader(&tar.Header{Name: "executor", Typeflag: tar.TypeReg, Mode: 0555, Uid: 1000, Gid: 1000, Size: int64(len(data))}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(data); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func workspaceOptions(bytes, inodes int64) map[string]string {
	return map[string]string{"type": "tmpfs", "device": "tmpfs", "o": fmt.Sprintf("size=%d,nr_inodes=%d,uid=1000,gid=1000,mode=0755,nodev,nosuid", bytes, inodes)}
}

func (d *Docker) CreateActionVolume(ctx context.Context, name string, labels map[string]string, bytes, inodes int64) error {
	if err := d.do(ctx, http.MethodPost, "/volumes/create", nil, map[string]any{"Name": name, "Driver": "local", "Labels": labels, "DriverOpts": workspaceOptions(bytes, inodes)}, nil); err != nil {
		return err
	}
	return d.VerifyActionVolume(ctx, name, labels, workspaceOptions(bytes, inodes))
}

func (d *Docker) VerifyActionVolume(ctx context.Context, name string, labels, options map[string]string) error {
	var actual Volume
	if err := d.do(ctx, http.MethodGet, "/volumes/"+url.PathEscape(name), nil, nil, &actual); err != nil {
		return err
	}
	if actual.Name != name || actual.Driver != "local" || !actionLabelsMatch(actual.Labels, labels) || !reflect.DeepEqual(actual.Options, options) && !(len(actual.Options) == 0 && len(options) == 0) {
		return errors.New("action volume differs from planned ownership or bounds")
	}
	return nil
}

func holderSpec(image, volume, bootstrap string, labels map[string]string) Spec {
	return Spec{Image: image, Entrypoint: []string{"/bootstrap/executor"}, Cmd: []string{"hold-workspace"}, User: "1000:1000", Labels: labels, Volume: volume, VolumePath: "/work", VolumeNoCopy: true, VolumeReadOnly: true, BootstrapVolume: bootstrap, WorkDir: "/", Network: "none", ReadOnly: true, ActionControl: true, NanoCPUs: runnerclient.ActionHolderCPUs, MemoryBytes: runnerclient.ActionHolderMemory, PidsLimit: runnerclient.ActionHolderPids}
}
