//go:build !linux

package container

import (
	"context"
	"errors"
)

type podmanProfile struct{ path string }

func newPodmanProfile(context.Context, string) (*podmanProfile, error) {
	return nil, errors.New("Podman sandbox qualification requires Linux")
}
func (*podmanProfile) validate() error {
	return errors.New("Podman sandbox qualification requires Linux")
}
func (*podmanProfile) inspectOCI(string, string, string) error {
	return errors.New("Podman sandbox qualification requires Linux")
}
func (*podmanProfile) inspectAllocationOCI(string,string,string) (bool,error) {return false,errors.New("Podman qualification requires Linux")}
func (*podmanProfile) hostIdentity() (string, error) {
	return "", errors.New("Podman qualification requires Linux")
}
func (*podmanProfile) inspectAnchor(string, string, Spec, int) (string, string, error) {
	return "", "", errors.New("Podman qualification requires Linux")
}
