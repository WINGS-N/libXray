package libXray

import (
	"net/netip"
	"sync"
	"time"
)

// The per-app routing of Android rests on the core knowing which app owns a
// connection. The core asks for the name of the owning process and matches it
// against the "process" field of the routing rules, so the UID goes in as that
// name, in decimal. Rules of the app are written against it, and an owner that
// stays unknown comes through as "-1", which a rule can match as well.
//
// Resolution has to be cheap: the core asks once per rule that carries a
// process field, for every new connection, and on Android every answer that is
// not cached costs a round trip into system_server. Hence the cache, keyed by
// the whole flow, and hence the window: an app that opens sockets one after
// another (Tor pulling several guards at once) is seen by the core before the
// kernel has published the socket, and the first look misses.

const (
	// uidCacheTTL is how long a resolved owner is reused. A live connection
	// does not change hands, and a port that comes back is a different flow
	uidCacheTTL = 30 * time.Second
	// uidMissTTL is the same for an owner that stayed unknown. Short, because
	// what is missing now may be published a moment later
	uidMissTTL = 2 * time.Second
	// uidRetryInterval is how often the tables are read again inside the window
	uidRetryInterval = 5 * time.Millisecond
	// uidCacheLimit is when what has expired is swept
	uidCacheLimit = 4096
	// sdkConnectionOwner is the first Android that answers
	// ConnectivityManager.getConnectionOwnerUid. Below it the /proc tables are
	// still readable by an untrusted app, above it they are not
	sdkConnectionOwner = 30
)

type uidCacheEntry struct {
	uid       int32
	expiresAt time.Time
}

// UIDFinder resolves the owner of a connection outside the core. On Android it
// is backed by ConnectivityManager.getConnectionOwnerUid, the only API that
// lets a VPN app see the UID behind a connection of its own tunnel. It returns
// -1 when the connection is unknown to it.
type UIDFinder interface {
	FindProcessByConnection(network, srcIP string, srcPort int, destIP string, destPort int) int
}

var (
	uidMu         sync.Mutex
	uidCache      = make(map[string]uidCacheEntry)
	uidFinder     UIDFinder
	uidSdkVersion int
	uidTimeout    time.Duration
)

func lookupUID(network, srcIP string, srcPort uint16, destIP string, destPort uint16) int32 {
	src, ok := endpoint(srcIP, srcPort)
	if !ok {
		return -1
	}
	dst, ok := endpoint(destIP, destPort)
	if !ok {
		return -1
	}
	key := network + "|" + src.String() + ">" + dst.String()
	if uid, found := readUIDCache(key); found {
		return uid
	}

	uidMu.Lock()
	finder, sdkVersion, timeout := uidFinder, uidSdkVersion, uidTimeout
	uidMu.Unlock()

	uid := resolveUID(finder, sdkVersion, network, src, dst)
	if uid < 0 && timeout > 0 {
		deadline := time.Now().Add(timeout)
		for uid < 0 {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				break
			}
			time.Sleep(min(uidRetryInterval, remaining))
			uid = resolveUID(finder, sdkVersion, network, src, dst)
		}
	}
	writeUIDCache(key, uid)
	return uid
}

func resolveUID(finder UIDFinder, sdkVersion int, network string, src, dst netip.AddrPort) int32 {
	if finder != nil && sdkVersion >= sdkConnectionOwner {
		uid := finder.FindProcessByConnection(
			network,
			src.Addr().String(),
			int(src.Port()),
			dst.Addr().String(),
			int(dst.Port()),
		)
		if uid >= 0 {
			return int32(uid)
		}
	}
	// under root the tables answer for every app, and below
	// sdkConnectionOwner they are all there is
	return scanProcTables(network == "tcp", src.Addr(), encodeAddrPort(src), encodeAddrPort(dst))
}

func endpoint(ip string, port uint16) (netip.AddrPort, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr.Unmap(), port), true
}

func readUIDCache(key string) (int32, bool) {
	uidMu.Lock()
	defer uidMu.Unlock()
	entry, ok := uidCache[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return -1, false
	}
	return entry.uid, true
}

func writeUIDCache(key string, uid int32) {
	ttl := uidCacheTTL
	if uid < 0 {
		ttl = uidMissTTL
	}
	uidMu.Lock()
	defer uidMu.Unlock()
	if len(uidCache) >= uidCacheLimit {
		now := time.Now()
		for cached, entry := range uidCache {
			if now.After(entry.expiresAt) {
				delete(uidCache, cached)
			}
		}
	}
	uidCache[key] = uidCacheEntry{uid: uid, expiresAt: time.Now().Add(ttl)}
}
