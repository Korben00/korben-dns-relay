package relay

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	QueryPath = "/v1/query"
	MediaType = "application/octet-stream"
	maxQuery  = 1232
	maxFrame  = 18 + maxQuery
)

var errWire = errors.New("invalid DNS message")

type packet struct {
	target netip.Addr
	tcp    bool
	wire   []byte
	end    int
}

func parseFrame(b []byte) (packet, error) {
	if len(b) < 2 || len(b) > maxFrame || b[0] > 1 {
		return packet{}, errWire
	}
	var target netip.Addr
	var off int
	switch b[1] {
	case 4:
		off = 6
		if len(b) < off {
			return packet{}, errWire
		}
		target = netip.AddrFrom4([4]byte(b[2:off]))
	case 6:
		off = 18
		if len(b) < off {
			return packet{}, errWire
		}
		target = netip.AddrFrom16([16]byte(b[2:off]))
		if target.Is4In6() {
			return packet{}, errWire
		}
	default:
		return packet{}, errWire
	}
	w := b[off:]
	end, err := checkQuery(w)
	if err != nil {
		return packet{}, err
	}
	return packet{target: target, tcp: b[0] == 1, wire: w, end: end}, nil
}

// Both messages must have a single uncompressed question. A name in the
// first question has no preceding name to which it could point.
func questionEnd(w []byte) (int, error) {
	if len(w) < 17 || binary.BigEndian.Uint16(w[4:6]) != 1 {
		return 0, errWire
	}
	i := 12
	for {
		if i >= len(w) || i-12 >= 255 {
			return 0, errWire
		}
		n := int(w[i])
		i++
		if n == 0 {
			break
		}
		if n > 63 || i+n >= len(w) || i+n-12 >= 255 {
			return 0, errWire
		}
		i += n
	}
	if len(w)-i < 4 {
		return 0, errWire
	}
	return i + 4, nil
}

func checkQuery(w []byte) (int, error) {
	if len(w) > maxQuery {
		return 0, errWire
	}
	end, err := questionEnd(w)
	if err != nil {
		return 0, err
	}
	flags := binary.BigEndian.Uint16(w[2:4])
	qt := binary.BigEndian.Uint16(w[end-4 : end-2])
	if flags&^0x0030 != 0 || binary.BigEndian.Uint32(w[6:10]) != 0 ||
		binary.BigEndian.Uint16(w[end-2:end]) != 1 || qt == 0 || qt == 41 ||
		(qt >= 249 && qt <= 255) || qt == 65535 {
		return 0, errWire
	}
	switch binary.BigEndian.Uint16(w[10:12]) {
	case 0:
		if end != len(w) {
			return 0, errWire
		}
	case 1:
		opt := w[end:]
		// Single EDNS(0) OPT, no extended status and only the DO bit.
		if len(opt) < 11 || opt[0] != 0 || binary.BigEndian.Uint16(opt[1:3]) != 41 ||
			binary.BigEndian.Uint32(opt[5:9])&^0x8000 != 0 ||
			int(binary.BigEndian.Uint16(opt[9:11])) != len(opt)-11 {
			return 0, errWire
		}
		size := binary.BigEndian.Uint16(opt[3:5])
		if size < 512 || size > 1232 {
			return 0, errWire
		}
		// Reject all optional data except one zero-filled Padding option.
		// In particular no ECS, cookies, or opaque bytes.
		data := opt[11:]
		if len(data) > 0 {
			if len(data) < 4 || binary.BigEndian.Uint16(data[:2]) != 12 ||
				int(binary.BigEndian.Uint16(data[2:4])) != len(data)-4 {
				return 0, errWire
			}
			for _, v := range data[4:] {
				if v != 0 {
					return 0, errWire
				}
			}
		}
	default:
		return 0, errWire
	}
	return end, nil
}

func udpLimit(p packet) int {
	if p.end == len(p.wire) {
		return 512
	}
	return int(binary.BigEndian.Uint16(p.wire[p.end+3 : p.end+5]))
}

func responseMatches(p packet, w []byte) bool {
	end, err := questionEnd(w)
	if err != nil || end != p.end || w[0] != p.wire[0] || w[1] != p.wire[1] ||
		w[2]&0xf8 != 0x80 {
		return false
	}
	// Case-insensitive comparison only inside labels, never in QTYPE/QCLASS.
	for i := 12; i < end-4; i++ {
		if asciiLower(w[i]) != asciiLower(p.wire[i]) {
			return false
		}
	}
	for i := end - 4; i < end; i++ {
		if w[i] != p.wire[i] {
			return false
		}
	}
	return true
}

func asciiLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}
