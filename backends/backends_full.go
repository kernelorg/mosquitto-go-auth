//go:build !minimal

package backends

import (
	"fmt"

	"github.com/iegomez/mosquitto-go-auth/hashing"
	log "github.com/sirupsen/logrus"
)

// BuildVariant tells which set of backends was compiled in.
const BuildVariant = "full"

// newBackend builds the backend named bename. Every backend is available in
// the default build; see backends_minimal.go for the "minimal" build tag.
func newBackend(bename string, authOpts map[string]string, logLevel log.Level, hasher hashing.HashComparer, version string) (Backend, error) {
	switch bename {
	case postgresBackend:
		return NewPostgres(authOpts, logLevel, hasher)
	case jwtBackend:
		return NewJWT(authOpts, logLevel, hasher, version)
	case filesBackend:
		return NewFiles(authOpts, logLevel, hasher)
	case redisBackend:
		return NewRedis(authOpts, logLevel, hasher)
	case mysqlBackend:
		return NewMysql(authOpts, logLevel, hasher)
	case httpBackend:
		return NewHTTP(authOpts, logLevel, version)
	case sqliteBackend:
		return NewSqlite(authOpts, logLevel, hasher)
	case mongoBackend:
		return NewMongo(authOpts, logLevel, hasher)
	case grpcBackend:
		return NewGRPC(authOpts, logLevel)
	case jsBackend:
		return NewJavascript(authOpts, logLevel)
	case ldapBackend:
		return NewLDAP(authOpts, logLevel)
	case pluginBackend:
		return NewCustomPlugin(authOpts, logLevel)
	case radiusBackend:
		return NewRADIUS(authOpts, logLevel)
	default:
		return nil, fmt.Errorf("unknown backend %s", bename)
	}
}
