// The pieces upstream dropped that the WINGS V app still needs.
//
// Upstream funnelled everything through Invoke and removed the environment
// setup along the way, but the Android side has two things Invoke has no place
// for: a TUN descriptor handed over by the VpnService, and an asset directory
// that has to be in place before the core reads geo files. Both are process
// environment, not request payload, so they live here rather than in a request.
package libXray

import (
	"encoding/json"
	"os"
	"strconv"

	"github.com/xtls/libxray/geo"
	"github.com/xtls/xray-core/common/platform"
)

// SetTunFd hands the TUN descriptor to the core. Call it before starting Xray:
// the core reads the descriptor once, while the inbound is being built.
func SetTunFd(fd int32) {
	_ = os.Setenv(platform.TunFdKey, strconv.Itoa(int(fd)))
}

// SetAssetDir points the core at the geo files. Upstream used to carry this in
// the run request and no longer does, so it is set on its own.
func SetAssetDir(dir string) {
	_ = os.Setenv(platform.AssetLocation, dir)
	_ = os.Setenv(platform.CertLocation, dir)
}

// ReadGeoFiles reports which geo files a config actually references, so the app
// can ship only those. Upstream removed it; the app still thins its assets.
func ReadGeoFiles(configJSON string) string {
	domain, ip := geo.ReadGeoFiles([]byte(configJSON))
	out, err := json.Marshal(map[string]any{"domain": domain, "ip": ip})
	if err != nil {
		return "{}"
	}
	return string(out)
}
