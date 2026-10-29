package backends

import (
	"context"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// RedisClient and SingleRedisClient are shared with the cache package, so they
// are compiled into every build variant (see backends_minimal.go).

type RedisClient interface {
	Get(ctx context.Context, key string) *goredis.StringCmd
	SMembers(ctx context.Context, key string) *goredis.StringSliceCmd
	Ping(ctx context.Context) *goredis.StatusCmd
	Close() error
	FlushDB(ctx context.Context) *goredis.StatusCmd
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *goredis.StatusCmd
	SAdd(ctx context.Context, key string, members ...interface{}) *goredis.IntCmd
	Expire(ctx context.Context, key string, expiration time.Duration) *goredis.BoolCmd
	ReloadState(ctx context.Context)
}

type SingleRedisClient struct {
	*goredis.Client
}

func (c *SingleRedisClient) ReloadState(ctx context.Context) {
	// NO-OP for single node clients
}
