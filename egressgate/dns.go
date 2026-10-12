package egressgate

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

// DNS response codes and flags the sinkhole uses.
const (
	dnsRefused = 5
	dnsMaxName = 253
)

// ServeDNS answers every query on pc with REFUSED and records the lookup as
// a denial against the job it came from. A job can only get to the network
// through the proxy, so a lookup the proxy did not make is a tool ignoring
// HTTPS_PROXY, and the recorded denial is what turns its silent failure
// into a line in the job's log. It returns when pc is closed.
func (g *Gateway) ServeDNS(pc net.PacketConn) error {
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		name, resp, ok := refuse(buf[:n])
		if !ok {
			continue
		}
		if src, ok := addrOf(from); ok {
			if j := g.find(src); j != nil {
				g.recordLookup(j, name)
			}
		}
		_, _ = pc.WriteTo(resp, from)
	}
}

// recordLookup records a DNS lookup as a denial: a host that is on the
// list was looked up directly, and one that is not is plainly not allowed.
func (g *Gateway) recordLookup(j *jobState, name string) {
	d := Denial{Host: name, Method: "DNS", Reason: reasonDirect}
	for _, a := range j.allow {
		if ok, _ := a.match(name, a.Port); ok {
			g.record(j, d)
			return
		}
	}
	d.Reason, d.Port = "", HTTPSPort
	g.record(j, d)
}

// refuse builds the REFUSED answer to a query, and returns the name asked
// for. ok is false for something that is not a standard query.
func refuse(q []byte) (name string, resp []byte, ok bool) {
	if len(q) < 12 || q[2]&0x80 != 0 || (q[2]>>3)&0xF != 0 || binary.BigEndian.Uint16(q[4:6]) != 1 {
		return "", nil, false
	}
	var labels []string
	i := 12
	for {
		if i >= len(q) {
			return "", nil, false
		}
		l := int(q[i])
		if l == 0 {
			i++
			break
		}
		if l&0xC0 != 0 || i+1+l > len(q) {
			return "", nil, false
		}
		labels = append(labels, string(q[i+1:i+1+l]))
		i += 1 + l
	}
	if i+4 > len(q) {
		return "", nil, false
	}
	end := i + 4
	name = strings.ToLower(strings.Join(labels, "."))
	if len(name) > dnsMaxName {
		return "", nil, false
	}
	resp = make([]byte, end)
	copy(resp, q[:end])
	// QR, the opcode and RD as asked, RA, and the REFUSED rcode; no records.
	resp[2] = 0x80 | q[2]&0x79
	resp[3] = 0x80 | dnsRefused
	binary.BigEndian.PutUint16(resp[6:], 0)
	binary.BigEndian.PutUint16(resp[8:], 0)
	binary.BigEndian.PutUint16(resp[10:], 0)
	return name, resp, true
}
