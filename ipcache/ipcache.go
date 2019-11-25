// Package ipcache provides a time-based cache object to keep track of recently-seen IP addresses.
package ipcache

import (
	"context"
	"flag"
	"fmt"
	"sync"
	"time"

	"github.com/m-lab/traceroute-caller/connection"
)

var (
	// IPCacheTimeout sets a lower bound on the amount of time between subsequent traceroutes to a single IP address.
	IPCacheTimeout = flag.Duration("IPCacheTimeout", 120*time.Second, "Timeout duration in seconds for IPCache")

	// IPCacheUpdatePeriod determines how long to wait between cache-scrubbing attempts.
	IPCacheUpdatePeriod = flag.Duration("IPCacheUpdatePeriod", 1*time.Second, "We run the cache eviction loop with this frequency")
)

// Tracer is the generic interface for all things that can perform a traceroute.
type Tracer interface {
	Trace(conn connection.Connection, t time.Time) string
	CreateCacheTest(conn connection.Connection, t time.Time, cachedTest string)
}

// cachedTest is a single entry in the cache of traceroute results.
type cachedTest struct {
	timeStamp time.Time
	data      string
	done      chan struct{}
}

// RecentIPCache contains a list of all the IP addresses that we have traced to
// recently. We keep this list to ensure that we don't traceroute to the same
// location repeatedly at a high frequency.
type RecentIPCache struct {
	cache map[string]*cachedTest
	mu    sync.RWMutex

	tracer Tracer
}

// Trace performs a trace and adds it to the cache.
func (rc *RecentIPCache) Trace(conn connection.Connection) {
	ip := conn.RemoteIP
	rc.mu.Lock()
	_, ok := rc.cache[ip]
	if !ok {
		nc := &cachedTest{
			timeStamp: time.Now(),
			done:      make(chan struct{}),
		}
		rc.cache[ip] = nc
		rc.mu.Unlock()

		nc.data = rc.tracer.Trace(conn, nc.timeStamp)
		close(nc.done)
		return
	}
	rc.mu.Unlock()
	rc.tracer.CreateCacheTest(conn, time.Now(), rc.GetData(ip))
}

// GetCacheLength returns the number of items currently in the cache. The
// primary use of this is for testing, to ensure that something was put into or
// removed from the cache.
func (rc *RecentIPCache) GetCacheLength() int {
	return len(rc.cache)
}

// GetData will wait till the test content available if there is an entry
// in cache.
func (rc *RecentIPCache) GetData(ip string) string {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	c, ok := rc.cache[ip]
	if ok {
		<-c.done
		return c.data
	}
	return ""
}

// New creates and returns a RecentIPCache. It also starts up a background
// goroutine that scrubs the cache.
func New(ctx context.Context, tracer Tracer, ipCacheTimeout, ipCacheUpdatePeriod time.Duration) *RecentIPCache {
	m := &RecentIPCache{
		cache:  make(map[string]*cachedTest),
		tracer: tracer,
	}
	go func() {
		ticker := time.NewTicker(ipCacheUpdatePeriod)
		defer ticker.Stop()
		for now := range ticker.C {
			if ctx.Err() != nil {
				return
			}
			for k, v := range m.cache {
				if now.Sub(v.timeStamp) > ipCacheTimeout {
					fmt.Println("try to delete " + k)
					m.mu.Lock()
					delete(m.cache, k)
					fmt.Println("delete done")
					m.mu.Unlock()
				}
			}
		}

	}()
	return m
}
