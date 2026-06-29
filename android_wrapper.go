//go:build android

package libXray

import (
	"net/netip"

	c "github.com/xtls/libxray/controller"
	xtun "github.com/xtls/xray-core/proxy/tun"
)

type DialerController interface {
	ProtectFd(int) bool
}

// ProcessFinder is an interface for Android process finding functionality.
// Apps should implement FindProcessByConnection()
// and pass the implementation to RegisterProcessFinder() before starting the core.
type ProcessFinder interface {
	// FindProcessByConnection finds the UID of the process that owns the given connection.
	//
	// network: Protocol type: "tcp" or "udp"
	// srcIP: Source IP address
	// srcPort: Source port
	// destIP: Destination IP address
	// destPort: Destination port
	// Returns the UID of the owning process, or -1 if not found.
	FindProcessByConnection(network, srcIP string, srcPort int, destIP string, destPort int) int
}

func RegisterDialerController(controller DialerController) {
	c.RegisterDialerController(func(fd uintptr) {
		controller.ProtectFd(int(fd))
	})
}

func RegisterListenerController(controller DialerController) {
	c.RegisterListenerController(func(fd uintptr) {
		controller.ProtectFd(int(fd))
	})
}

// RegisterProcessFinder registers an Android process finder with Xray-core,
// enabling per-app routing based on UID. Must be called before starting the
// core for process-based routing rules to work.
// Pass nil to unregister a previously registered finder.
func RegisterProcessFinder(finder ProcessFinder) {
	if finder == nil {
		c.RegisterProcessFinder(nil)
		return
	}

	c.RegisterProcessFinder(func(network, srcIP string, srcPort int, destIP string, destPort int) int {
		return finder.FindProcessByConnection(network, srcIP, srcPort, destIP, destPort)
	})
}

// UIDLookupController resolves the owning UID of a connection observed by the
// xray TUN inbound. Backed by ConnectivityManager.getConnectionOwnerUid() on
// Android - the only non-root API that lets a VPN app see UIDs of connections
// routed through its own tunnel. Both the local (TUN-side) and remote
// (gVisor-side) endpoints are passed as 4 or 16 byte big-endian addresses so
// the Java side can build InetSocketAddress without reparsing.
//
// Implementations must return -1 when the lookup fails so xray falls through
// to its other resolution paths (/proc/net/tcp in root TPROXY mode) and
// finally to "unknown UID -> not filtered" to keep the tunnel alive.
type UIDLookupController interface {
	// LookupConnectionUID resolves the owning UID. local/remote are the
	// connection endpoints encoded as "ip:port" (gomobile binds strings
	// reliably across the JNI boundary; raw []byte parameters in interface
	// methods are silently dropped by gobind in some configurations, which
	// would prevent the export). Returns -1 when the lookup fails.
	LookupConnectionUID(protocol int, local string, remote string) int32
}

// SetUIDLookupDiagPath enables the Go-side UID lookup diagnostic to write into
// the given file path. Used by debug builds to verify that the registered
// callback is invoked at all - Android typically suppresses stderr from app
// processes, so we route Go-side diag entries into a known file the app can
// read back via run-as. Empty path disables.
func SetUIDLookupDiagPath(path string) {
	xtun.SetUIDLookupDiagPath(path)
}

func RegisterUIDLookupController(controller UIDLookupController) {
	if controller == nil {
		xtun.SetUIDLookupCallback(nil)
		return
	}
	xtun.SetUIDLookupCallback(func(protocol int, src netip.AddrPort, dst netip.AddrPort) int32 {
		return controller.LookupConnectionUID(protocol, src.String(), dst.String())
	})
}
