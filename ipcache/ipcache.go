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
	// IPCacheTimeout sets a lower bound on the amount of time
	// between subsequent traceroutes to a single IP address.
	// Traceroutes typically take 5 to 10 minutes.
	IPCacheTimeout = flag.Duration("IPCacheTimeout", 10*time.Minute, "Timeout duration in seconds for IPCache")

	// IPCacheUpdatePeriod determines how long to wait between
	// cache-scrubbing attempts.
	IPCacheUpdatePeriod = flag.Duration("IPCacheUpdatePeriod", 1*time.Minute, "We run the IP cache eviction loop with this frequency")
)

// Tracer is the generic interface for all things that can perform a traceroute.
type Tracer interface {
	Trace(conn connection.Connection, t time.Time) ([]byte, error)
	TraceFromCachedTrace(conn connection.Connection, t time.Time, cachedTest []byte) error
	DontTrace(conn connection.Connection, err error)
}

// cachedTest is a single entry in the cache of traceroute results.
type cachedTest struct {
	timeStamp time.Time
	data      []byte
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

func (rc *RecentIPCache) getTracer() Tracer {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.tracer
}

// Trace performs a trace and adds it to the cache. It calls the methods of the
// tracer, so if those create files on disk, then files on disk will be created
// as a side effect.
func (rc *RecentIPCache) Trace(conn connection.Connection) ([]byte, error) {
	c, cached := rc.getEntry(conn.RemoteIP)
	t := rc.getTracer()
	if cached {
		<-c.dataReady
		if c.err == nil {
			_ = t.TraceFromCachedTrace(conn, time.Now(), c.data)
			return c.data, nil
		}
		t.DontTrace(conn, c.err)
		return nil, c.err
	}
	c.data, c.err = t.Trace(conn, c.timeStamp)
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

// UpdateTracer switches the Tracer being used.
func (rc *RecentIPCache) UpdateTracer(t Tracer) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.tracer = t
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
					// Note that if there is a trace in progress, the events
					// waiting for it to complete will still get the result
					// and save it.  But this allows a new trace to be started
					// on the same IP address.
					delete(m.cache, k)
				}
			}
			m.mu.Unlock()
		}

	}()
	return m
}
