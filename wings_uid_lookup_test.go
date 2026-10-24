package libXray

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// stubFinder answers as the Java side would, counting what it was asked
type stubFinder struct {
	uid   int32
	calls atomic.Int32
	// missesFirst is how many of the first answers are a miss, as a kernel
	// that has not published the socket yet makes it look
	missesFirst int32
}

func (f *stubFinder) FindProcessByConnection(_, _ string, _ int, _ string, _ int) int {
	if f.calls.Add(1) <= f.missesFirst {
		return -1
	}
	return int(f.uid)
}

func withFinder(t *testing.T, finder UIDFinder, timeout time.Duration) {
	t.Helper()
	uidMu.Lock()
	uidFinder, uidSdkVersion, uidTimeout = finder, sdkConnectionOwner, timeout
	uidCache = make(map[string]uidCacheEntry)
	uidMu.Unlock()
	t.Cleanup(func() {
		uidMu.Lock()
		uidFinder, uidSdkVersion, uidTimeout = nil, 0, 0
		uidCache = make(map[string]uidCacheEntry)
		uidMu.Unlock()
	})
}

// The owner of a connection is resolved once and then taken from the cache.
func TestLookupUIDCachesTheOwnerOfAFlow(t *testing.T) {
	finder := &stubFinder{uid: 10123}
	withFinder(t, finder, 0)

	for range 3 {
		if uid := lookupUID("tcp", "10.0.0.2", 40100, "93.184.216.34", 443); uid != 10123 {
			t.Fatalf("resolved uid %d, want 10123", uid)
		}
	}
	if got := finder.calls.Load(); got != 1 {
		t.Fatalf("the owner was asked for %d times, want 1", got)
	}
}

// A flow of its own is resolved on its own, cache or no cache.
func TestLookupUIDKeepsFlowsApart(t *testing.T) {
	finder := &stubFinder{uid: 10123}
	withFinder(t, finder, 0)

	lookupUID("tcp", "10.0.0.2", 40101, "93.184.216.34", 443)
	lookupUID("tcp", "10.0.0.2", 40102, "93.184.216.34", 443)
	lookupUID("udp", "10.0.0.2", 40101, "93.184.216.34", 443)
	if got := finder.calls.Load(); got != 3 {
		t.Fatalf("the owner was asked for %d times, want 3", got)
	}
}

// A lookup that misses is retried inside the window and then answers.
func TestLookupUIDRetriesInsideTheWindow(t *testing.T) {
	finder := &stubFinder{uid: 10123, missesFirst: 3}
	withFinder(t, finder, 200*time.Millisecond)

	if uid := lookupUID("tcp", "10.0.0.2", 40103, "93.184.216.34", 443); uid != 10123 {
		t.Fatalf("resolved uid %d after the retries, want 10123", uid)
	}
	if got := finder.calls.Load(); got < 4 {
		t.Fatalf("the owner was asked for %d times, want the misses plus one", got)
	}
}

// Without a window a miss is answered as unknown right away, and the answer is
// not kept for long.
func TestLookupUIDTakesAMissAsUnknown(t *testing.T) {
	finder := &stubFinder{uid: 10123, missesFirst: 1 << 30}
	withFinder(t, finder, 0)

	if uid := lookupUID("tcp", "10.0.0.2", 40104, "93.184.216.34", 443); uid != -1 {
		t.Fatalf("resolved uid %d, want -1 for an owner that is unknown", uid)
	}
	uidMu.Lock()
	entry, ok := uidCache["tcp|10.0.0.2:40104>93.184.216.34:443"]
	uidMu.Unlock()
	if !ok {
		t.Fatal("the miss was not kept at all")
	}
	if kept := time.Until(entry.expiresAt); kept > uidMissTTL {
		t.Fatalf("the miss is kept for %s, longer than %s", kept, uidMissTTL)
	}
}

// An endpoint that is not an address resolves to nothing.
func TestLookupUIDRefusesAMalformedEndpoint(t *testing.T) {
	finder := &stubFinder{uid: 10123}
	withFinder(t, finder, 0)

	if uid := lookupUID("tcp", "not-an-ip", 40105, "93.184.216.34", 443); uid != -1 {
		t.Fatalf("resolved uid %d of a malformed endpoint, want -1", uid)
	}
	if got := finder.calls.Load(); got != 0 {
		t.Fatalf("the owner was asked for %d times for a malformed endpoint", got)
	}
}

// The /proc encoding is what the kernel writes: the words of the address
// reversed, the port in hex.
func TestEncodeAddrPortMatchesProc(t *testing.T) {
	for _, test := range []struct{ endpoint, want string }{
		{"10.0.0.2:40100", "0200000A:9CA4"},
		{"127.0.0.1:53", "0100007F:0035"},
		{"[fd00::2]:443", "000000FD000000000000000002000000:01BB"},
	} {
		addr, err := netip.ParseAddrPort(test.endpoint)
		if err != nil {
			t.Fatal(err)
		}
		if got := encodeAddrPort(addr); got != test.want {
			t.Fatalf("encoded %s as %q, want %q", test.endpoint, got, test.want)
		}
	}
}
