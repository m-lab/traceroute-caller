// Package ipcache provides a time-based cache object that contains
// the traceroute results of IP addresses that we have recently ran
// a traceroute to.
package ipcache

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/m-lab/uuid"
)

// Tracer is the generic interface for all things that can perform a traceroute.
type Tracer interface {
	Trace(remoteIP, cookie, uuid string, t time.Time) ([]byte, error)
	TraceFromCachedTrace(cookie, uuid string, t time.Time, cachedTest []byte) error
	DontTrace()
}

// Config contains configuration parameters of an IP cache.
// These parameters are presented to the user as IPCacheTimeout and
// IPCacheUpdatePeriod flags.  But these are confusing flag names because
// (1) IPCacheTimeout implies there is a timeout for the entire cache
// as opposed to an individual entry and (2) IPCacheUpdatePeriod implies
// the cache is routinely updated whereas it is routinely scanned but not
// necessarily updated.  For backward compatibility, flags names are kept
// the same but the fields below should be less confusing.
type Config struct {
	EntryTimeout time.Duration // IPCacheTimeout flag
	ScanPeriod   time.Duration // IPCacheUpdatePeriod flag
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
	tracetool Tracer
}

// New creates and returns an IPCache. It also starts up a background
// goroutine that scrubs the cache.
func New(ctx context.Context, tracetool Tracer, ipcCfg Config) (*IPCache, error) {
	if ctx == nil || tracetool == nil {
		return nil, fmt.Errorf("nil context or tracetool")
	}
	if ipcCfg.EntryTimeout == 0 || ipcCfg.ScanPeriod == 0 {
		return nil, fmt.Errorf("invalid IP cache configuration: %+v", ipcCfg)
	}
	ipc := &IPCache{
		cache:     make(map[string]*cachedTest),
		tracetool: tracetool,
	}
	go func() {
		ticker := time.NewTicker(ipcCfg.ScanPeriod)
		defer ticker.Stop()
		for now := range ticker.C {
			if ctx.Err() != nil {
				return
			}
			// Must hold lock while performing GC.
			ipc.cacheLock.Lock()
			for k, v := range ipc.cache {
				if now.Sub(v.timeStamp) > ipcCfg.EntryTimeout {
					// Note that if there is a trace in progress, the events
					// waiting for it to complete will still get the result
					// and save it.  But this allows a new trace to be started
					// on the same IP address.
					delete(ipc.cache, k)
				}
			}
			ipc.cacheLock.Unlock()
		}
	}()
	return ipc, nil
}

// FetchTrace checks the IP cache to determine if a recent traceroute to
// the remote IP exists or not. If a traceroute exists, it will be used.
// Otherwise, it calls the tracetool to run a new traceroute.
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
			ic.tracetool.DontTrace()
			return nil, cachedTest.err
		}
		_ = ic.tracetool.TraceFromCachedTrace(cookie, uuid, time.Now(), cachedTest.data)
		return cachedTest.data, nil
	}
	cachedTest.data, cachedTest.err = ic.tracetool.Trace(remoteIP, cookie, uuid, cachedTest.timeStamp)
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

// NumEntries returns the number of entries currently in the IP cache.
// The primary use of this is for testing.
func (ic *IPCache) NumEntries() int {
	ic.cacheLock.Lock()
	defer ic.cacheLock.Unlock()
	return len(ic.cache)
}
