//go:build android

package libXray

import (
	"strconv"
	"time"

	corenet "github.com/xtls/xray-core/common/net"
)

// RegisterUIDProcessFinder hands the core a resolver for the owner of a
// connection, so that routing rules can select apps by UID. finder is backed by
// ConnectivityManager.getConnectionOwnerUid and is only asked from
// sdkConnectionOwner on; below that the /proc tables answer. sdkVersion is
// Build.VERSION.SDK_INT, lookupTimeoutMs the window for retrying a lookup that
// misses, 0 for none. Pass a nil finder to unregister.
func RegisterUIDProcessFinder(finder ProcessFinder, sdkVersion int, lookupTimeoutMs int) {
	uidMu.Lock()
	uidFinder = finder
	uidSdkVersion = sdkVersion
	uidTimeout = time.Duration(lookupTimeoutMs) * time.Millisecond
	uidCache = make(map[string]uidCacheEntry)
	uidMu.Unlock()

	if finder == nil {
		corenet.RegisterAndroidProcessFinder(nil)
		return
	}
	corenet.RegisterAndroidProcessFinder(
		func(network, srcIP string, srcPort uint16, destIP string, destPort uint16) (int, string, string, error) {
			uid := int(lookupUID(network, srcIP, srcPort, destIP, destPort))
			// no error even when the owner is unknown: the core logs every one
			// of those, and a rule is meant to match the "-1" instead
			return uid, strconv.Itoa(uid), "", nil
		},
	)
}
