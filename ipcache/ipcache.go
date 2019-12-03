// Package ipcache provides a time-based cache object to keep track of recently-seen IP addresses.
package ipcache

import (
	"context"
	"flag"
	"log"
	"sync"
	"time"

	"github.com/m-lab/traceroute-caller/connection"
	"github.com/m-lab/traceroute-caller/scamper"
)

var (
	// IPCacheTimeout sets a lower bound on the amount of time between subsequent traceroutes to a single IP address.
	IPCacheTimeout = flag.Duration("IPCacheTimeout", 120*time.Second, "Timeout duration in seconds for IPCache")

	// IPCacheUpdatePeriod determines how long to wait between cache-scrubbing attempts.
	IPCacheUpdatePeriod = flag.Duration("IPCacheUpdatePeriod", 1*time.Second, "We run the cache eviction loop with this frequency")
)

type CacheTest struct {
	timeStamp time.Time
	data      string
	done      chan struct{}
}

// RecentIPCache contains a list of all the IP addresses that we have traced to
// recently. We keep this list to ensure that we don't traceroute to the same
// location repeatedly at a high frequency.
type RecentIPCache struct {
	cache map[string]*CacheTest
	mu    sync.RWMutex

	tracer scamper.Tracer
}

// Trace performs a trace and adds it to the cache.
func (rc *RecentIPCache) Trace(conn connection.Connection) {
	ip := conn.RemoteIP
	rc.mu.Lock()
	_, ok := rc.cache[ip]
	if !ok {
		nc := &CacheTest{
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
func New(ctx context.Context, tracer scamper.Tracer, ipCacheTimeout, ipCacheUpdatePeriod time.Duration) *RecentIPCache {
	m := &RecentIPCache{
		cache:  make(map[string]*CacheTest),
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
					log.Println("try to delete " + k)
					m.mu.Lock()
					delete(m.cache, k)
					log.Println("delete done")
					m.mu.Unlock()
				}
			}
		}

	}()
	return m
}
