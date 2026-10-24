//go:build !unix

package executor

import "errors"

func (p *egressProxy) startRuntimeProxy(string) (func(), error) {
	return nil, errors.New("private runtime HTTP sockets are unsupported on this host")
}
