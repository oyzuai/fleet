//go:build unix

package executor

import (
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// startRuntimeProxy exposes the existing job proxy through one private socket.
// The filesystem capability replaces its loopback password on this listener;
// every request still goes through the same proxy and enforced job gateway.
func (p *egressProxy) startRuntimeProxy(directory string) (func(), error) {
	if p.gateway == nil {
		return nil, errors.New("runtime HTTP inputs require an enforced job gateway")
	}
	path := filepath.Join(directory, "egress.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0o600); err != nil {
		listener.Close()
		return nil, err
	}
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := r.Clone(r.Context())
		request.Header = r.Header.Clone()
		request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(egressProxyUser+":"+p.secret)))
		p.ServeHTTP(w, request)
	})}
	go func() { _ = server.Serve(listener) }()
	return func() { _ = server.Close(); _ = listener.Close() }, nil
}
