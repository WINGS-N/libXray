//go:build android

package libXray

import (
	"errors"
	"net/netip"

	c "github.com/xtls/libxray/controller"
	"github.com/xtls/libxray/dns"
	xtun "github.com/xtls/xray-core/proxy/tun"
)

type DialerController interface {
	ProtectFd(int) bool
}

// SetDNS installs an Android VPN-aware process resolver. server must be an IP
// endpoint such as 8.8.8.8:53 or [2001:4860:4860::8888]:53.
func SetDNS(controller DialerController, server string) error {
	if controller == nil {
		return errors.New("dns dialer controller is nil")
	}
	return dns.SetDNS(server, func(fd uintptr) bool {
		return controller.ProtectFd(int(fd))
	})
}

// ResetDNS restores the resolver that was active before SetDNS.
func ResetDNS() {
	dns.ResetDNS()
}

// ProcessFinder -> implemented by apps to resolve UID from connection details.
// See RegisterProcessFinder.
type ProcessFinder interface {
	// FindProcessByConnection -> returns UID owning the connection, or -1.
	FindProcessByConnection(network, srcIP string, srcPort int, destIP string, destPort int) int
}

func RegisterDialerController(controller DialerController) {
	c.RegisterDialerController(func(fd uintptr) bool {
		return controller.ProtectFd(int(fd))
	})
}

func RegisterListenerController(controller DialerController) {
	c.RegisterListenerController(func(fd uintptr) bool {
		return controller.ProtectFd(int(fd))
	})
}

// RegisterProcessFinder -> registers process finder for per-app routing.
// Pass nil to unregister.
// sdkVersion = Build.VERSION.SDK_INT.
// On API < 30, /proc/net/* parsing is used automatically; the Java callback
// is only called on API 30+.
func RegisterProcessFinder(finder ProcessFinder, sdkVersion int) {
	if finder == nil {
		c.RegisterProcessFinder(nil, 0)
		return
	}

	c.RegisterProcessFinder(func(network, srcIP string, srcPort int, destIP string, destPort int) int {
		return finder.FindProcessByConnection(network, srcIP, srcPort, destIP, destPort)
	}, sdkVersion)
}

// UIDLookupController resolves the owning UID of a connection observed by the
// xray TUN inbound. Backed by ConnectivityManager.getConnectionOwnerUid() on
// Android - the only non-root API that lets a VPN app see UIDs of connections
// routed through its own tunnel. Both the local (TUN-side) and remote endpoints
// are passed so the Java side can build InetSocketAddress without reparsing.
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
