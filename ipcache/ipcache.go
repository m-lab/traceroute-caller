// Package ipcache provides a time-based cache object that contains
// the traceroute results of IP addresses that we have recently ran
// a traceroute to.
package ipcache

import (
	"context"
	"flag"
	"strconv"
	"sync"
	"time"

	"github.com/m-lab/uuid"
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
	Trace(remoteIP, cookie, uuid string, t time.Time) ([]byte, error)
	TraceFromCachedTrace(cookie, uuid string, t time.Time, cachedTest []byte) error
	DontTrace()
}

// cachedTest is a single entry in the cache of traceroute results.
type cachedTest struct {
	timeStamp time.Time
	data      []byte
	dataReady chan struct{}
	err       error
}

// IPCache contains a list of all the IP addresses that we have traced to
// recently. We keep this list to ensure that we don't traceroute to the same
// location repeatedly at a high frequency.
type IPCache struct {
	cache     map[string]*cachedTest
	cacheLock sync.Mutex
	tracer    Tracer
}

// New creates and returns an IPCache. It also starts up a background
// goroutine that scrubs the cache.
func New(ctx context.Context, tracer Tracer, ipCacheTimeout, ipCacheUpdatePeriod time.Duration) *IPCache {
	if ipCacheTimeout == 0 {
		ipCacheTimeout = *IPCacheTimeout
	}
	if ipCacheUpdatePeriod == 0 {
		ipCacheUpdatePeriod = *IPCacheUpdatePeriod
	}
	m := &IPCache{
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
			// Must hold lock while performing GC.
			m.cacheLock.Lock()
			for k, v := range m.cache {
				if now.Sub(v.timeStamp) > ipCacheTimeout {
					// Note that if there is a trace in progress, the events
					// waiting for it to complete will still get the result
					// and save it.  But this allows a new trace to be started
					// on the same IP address.
					delete(m.cache, k)
				}
			}
			m.cacheLock.Unlock()
		}
	}()
	return m
}

// FetchTrace checks the IP cache to determine if a recent traceroute to
// the remote IP exists or not. If a traceroute exists, it will be used.
// Otherwise, it calls the tracer to run a new traceroute.
func (ic *IPCache) FetchTrace(remoteIP, cookie string) ([]byte, error) {
	// Get a globally unique identifier for the given cookie.
	// For example, if cookie is "4418bb", we want something like:
	// "fd73893d272d_1633013267_unsafe_00000000004418BB".
	c, err := strconv.ParseUint(cookie, 16, 64)
	if err != nil {
		return nil, err
	}
	uuid := uuid.FromCookie(c)

	cachedTest, existed := ic.getEntry(remoteIP)
	if existed {
		<-cachedTest.dataReady
		if cachedTest.err != nil {
			ic.tracer.DontTrace()
			return nil, cachedTest.err
		}
		_ = ic.tracer.TraceFromCachedTrace(cookie, uuid, time.Now(), cachedTest.data)
		return cachedTest.data, nil
	}
	cachedTest.data, cachedTest.err = ic.tracer.Trace(remoteIP, cookie, uuid, cachedTest.timeStamp)
	close(cachedTest.dataReady)
	return cachedTest.data, cachedTest.err
}

// getEntry returns the entry in the IP cache corresponding to the given
// IP address. If the entry doesn't exist, a new one is created.
func (ic *IPCache) getEntry(ip string) (*cachedTest, bool) {
	ic.cacheLock.Lock()
	defer ic.cacheLock.Unlock()
	_, existed := ic.cache[ip]
	if !existed {
		ic.cache[ip] = &cachedTest{
			timeStamp: time.Now(),
			dataReady: make(chan struct{}),
		}
	}
	return ic.cache[ip], existed
}
