// Package ipcache provides a time-based cache object to keep track of recently-seen IP addresses.
package ipcache

import (
	"context"
	"flag"
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
	Trace(conn connection.Connection, t time.Time) (string, error)
	TraceFromCachedTrace(conn connection.Connection, t time.Time, cachedTest string) error
	DontTrace(conn connection.Connection, err error)
}

// cachedTest is a single entry in the cache of traceroute results.
type cachedTest struct {
	timeStamp time.Time
	data      string
	dataReady chan struct{}
	err       error
}

// RecentIPCache contains a list of all the IP addresses that we have traced to
// recently. We keep this list to ensure that we don't traceroute to the same
// location repeatedly at a high frequency.
type RecentIPCache struct {
	cache map[string]*cachedTest
	mu    sync.Mutex

	tracer Tracer
}

func (rc *RecentIPCache) getEntry(ip string) (*cachedTest, bool) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	_, existed := rc.cache[ip]
	if !existed {
		rc.cache[ip] = &cachedTest{
			timeStamp: time.Now(),
			dataReady: make(chan struct{}),
		}
	}
	return rc.cache[ip], existed
}

// Trace performs a trace and adds it to the cache. It calls the methods of the
// tracer, so if those create files on disk, then files on disk will be created
// as a side effect.
func (rc *RecentIPCache) Trace(conn connection.Connection) (string, error) {
	c, cached := rc.getEntry(conn.RemoteIP)
	if cached {
		<-c.dataReady
		if c.err == nil {
			rc.tracer.TraceFromCachedTrace(conn, time.Now(), c.data)
			return c.data, nil
		}
		rc.tracer.DontTrace(conn, c.err)
		return "", c.err
	}
	c.data, c.err = rc.tracer.Trace(conn, c.timeStamp)
	close(c.dataReady)
	return c.data, c.err
}

// GetCacheLength returns the number of items currently in the cache. The
// primary use of this is for testing, to ensure that something was put into or
// removed from the cache.
func (rc *RecentIPCache) GetCacheLength() int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return len(rc.cache)
}

// New creates and returns a RecentIPCache. It also starts up a background
// goroutine that scrubs the cache.
func New(ctx context.Context, trace Tracer, ipCacheTimeout, ipCacheUpdatePeriod time.Duration) *RecentIPCache {
	m := &RecentIPCache{
		cache:  make(map[string]*cachedTest),
		tracer: trace,
	}
	go func() {
		ticker := time.NewTicker(ipCacheUpdatePeriod)
		defer ticker.Stop()
		for now := range ticker.C {
			if ctx.Err() != nil {
				return
			}
			// Must hold lock while performing GC.
			m.mu.Lock()
			for k, v := range m.cache {
				if now.Sub(v.timeStamp) > ipCacheTimeout {
					delete(m.cache, k)
				}
			}
			m.mu.Unlock()
		}

	}()
	return m
}
