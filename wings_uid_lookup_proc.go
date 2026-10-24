package libXray

import (
	"bufio"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// The /proc/net UID lookup. Android hides other apps' socket tables from an
// untrusted app from API 29 on, so this only resolves anything below that and
// under root; above it the Java side answers through ConnectivityManager.

// scanProcTables walks the relevant /proc/net/* files, returning the first
// UID whose local/remote hex matches the connection.
//
// IPv4 sockets normally live in /proc/net/{tcp,udp} but apps that opened a
// dual-stack socket (AF_INET6 bound to ::ffff:0) show up under /proc/net/
// {tcp6,udp6} with the IPv4 address in the lower 32 bits and ::ffff:0/96 in
// the upper bits, so both representations are probed for IPv4 traffic.
func scanProcTables(tcp bool, srcAddr netip.Addr, srcHex, dstHex string) int32 {
	four, six := "/proc/net/tcp", "/proc/net/tcp6"
	if !tcp {
		four, six = "/proc/net/udp", "/proc/net/udp6"
	}
	if !srcAddr.Is4() {
		return scanFile(six, srcHex, dstHex)
	}
	if uid := scanFile(four, srcHex, dstHex); uid >= 0 {
		return uid
	}
	srcPort, srcWithoutPort := splitHexPort(srcHex)
	dstPort, dstWithoutPort := splitHexPort(dstHex)
	if srcWithoutPort == "" || dstWithoutPort == "" {
		return -1
	}
	mapPrefix := "00000000000000000000FFFF"
	return scanFile(six, mapPrefix+srcWithoutPort+":"+srcPort, mapPrefix+dstWithoutPort+":"+dstPort)
}

func splitHexPort(combined string) (port, addr string) {
	idx := strings.LastIndex(combined, ":")
	if idx < 0 {
		return "", ""
	}
	return combined[idx+1:], combined[:idx]
}

func scanFile(path, srcHex, dstHex string) int32 {
	f, err := os.Open(path)
	if err != nil {
		return -1
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	// a system with tens of thousands of sockets writes lines longer than the
	// default 64 KiB buffer
	scanner.Buffer(make([]byte, 0, 1024), 1024*1024)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}
		if !strings.EqualFold(fields[1], srcHex) || !strings.EqualFold(fields[2], dstHex) {
			continue
		}
		uid64, err := strconv.ParseInt(fields[7], 10, 32)
		if err != nil {
			continue
		}
		return int32(uid64)
	}
	return -1
}

// encodeAddrPort turns an endpoint into the /proc/net wire encoding: hex of the
// address bytes, every 32-bit word of it reversed, then ":PORT" in hex
func encodeAddrPort(addr netip.AddrPort) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	full, words := make([]byte, 0, 16), 4
	if addr.Addr().Is4() {
		four := addr.Addr().As4()
		full, words = append(full, four[:]...), 1
	} else {
		sixteen := addr.Addr().As16()
		full = append(full, sixteen[:]...)
	}
	buf := make([]byte, words*8)
	for word := 0; word < words; word++ {
		for i := 0; i < 4; i++ {
			byteVal := full[word*4+3-i]
			buf[word*8+i*2] = hexDigits[byteVal>>4]
			buf[word*8+i*2+1] = hexDigits[byteVal&0xF]
		}
	}
	b.Write(buf)
	b.WriteByte(':')
	port := addr.Port()
	b.Write([]byte{
		hexDigits[(port>>12)&0xF],
		hexDigits[(port>>8)&0xF],
		hexDigits[(port>>4)&0xF],
		hexDigits[port&0xF],
	})
	return b.String()
}
