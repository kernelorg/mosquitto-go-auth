//go:build minimal

package backends

import (
	"fmt"

	"github.com/iegomez/mosquitto-go-auth/hashing"
	log "github.com/sirupsen/logrus"
)

// BuildVariant tells which set of backends was compiled in.
const BuildVariant = "minimal"

// newBackend builds the backend named bename. The "minimal" build tag only
// compiles the files and radius backends, which keeps the plugin small (no
// database drivers, gRPC, LDAP or JavaScript interpreter): build with
//
//	go build -tags minimal -buildmode=c-shared -o go-auth.so .
func newBackend(bename string, authOpts map[string]string, logLevel log.Level, hasher hashing.HashComparer, version string) (Backend, error) {
	switch bename {
	case filesBackend:
		return NewFiles(authOpts, logLevel, hasher)
	case radiusBackend:
		return NewRADIUS(authOpts, logLevel)
	default:
		return nil, fmt.Errorf("backend %s is not included in this build (built with -tags minimal, only files and radius are available)", bename)
	}
}
