package readiness

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ServeCanary serves intentionally public, secret-free diagnostic metadata.
// It cannot launch work, accept evidence, forward requests or reveal tenant data.
func ServeCanary(ctx context.Context, httpAddr, dnsAddr, dnsName string) error {
	ln, err := net.Listen("tcp", httpAddr)
	if err != nil {
		return err
	}
	defer ln.Close()
	udp, err := net.ListenPacket("udp", dnsAddr)
	if err != nil {
		return err
	}
	defer udp.Close()
	tcp, err := net.Listen("tcp", dnsAddr)
	if err != nil {
		return err
	}
	defer tcp.Close()
	question, err := dnsQuestion(dnsName)
	if err != nil {
		return err
	}
	response := func(q []byte) []byte {
		if len(q) != len(question) || len(q) < 12 || string(q[12:]) != string(question[12:]) {
			return nil
		}
		b := append([]byte{}, q...)
		b[2] = 0x81
		b[3] = 0x80
		b[6] = 0
		b[7] = 1
		return append(b, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 192, 0, 2, 1)
	}
	srv := &http.Server{ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, MaxHeaderBytes: 4096, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := strings.TrimPrefix(r.URL.Path, "/probe/")
		if r.Method != "GET" || !strings.HasPrefix(r.URL.Path, "/probe/") || len(nonce) < 16 || len(nonce) > 64 || strings.Trim(nonce, "0123456789abcdef") != "" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, "oyzu-readiness:"+nonce)
	})}
	go func() { _ = srv.Serve(ln) }()
	go func() {
		b := make([]byte, 512)
		for {
			n, a, e := udp.ReadFrom(b)
			if e != nil {
				return
			}
			if out := response(b[:n]); out != nil {
				_, _ = udp.WriteTo(out, a)
			}
		}
	}()
	slots := make(chan struct{}, 64)
	go func() {
		for {
			c, e := tcp.Accept()
			if e != nil {
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				_ = c.Close()
				continue
			}
			go func() {
				defer func() { <-slots }()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				var h [2]byte
				if _, e := io.ReadFull(c, h[:]); e != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(h[:]))
				if n < 12 || n > 512 {
					return
				}
				b := make([]byte, n)
				if _, e := io.ReadFull(c, b); e != nil {
					return
				}
				out := response(b)
				if out == nil {
					return
				}
				binary.BigEndian.PutUint16(h[:], uint16(len(out)))
				_, _ = c.Write(append(h[:], out...))
			}()
		}
	}()
	<-ctx.Done()
	_ = srv.Close()
	return nil
}
