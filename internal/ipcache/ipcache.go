// Package ipcache provides a time-based cache object that contains
// the traceroute results of IP addresses that we have recently ran
// a traceroute to.
package ipcache

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Tracer is the generic interface for all things that can perform a traceroute.
type Tracer interface {
	Trace(remoteIP, uuid string, t time.Time) ([]byte, error)
	CachedTrace(uuid string, t time.Time, cachedTrace []byte) ([]byte, error)
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

// cachedTrace is a single entry in the cache of traceroute results.
type cachedTrace struct {
	timeStamp time.Time
	data      []byte
	dataReady chan struct{}
	err       error
}

// IPCache contains a list of all the IP addresses that we have traced to
// recently. We keep this list to ensure that we don't traceroute to the same
// location repeatedly at a high frequency.
type IPCache struct {
	cache     map[string]*cachedTrace
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
		cache:     make(map[string]*cachedTrace),
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
					// Note that if there is a traceroute in progress, the events
					// waiting for it to complete will still get the result
					// and save it.  But this allows a new traceroute to be started
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
func (ic *IPCache) FetchTrace(remoteIP, uuid string) ([]byte, error) {
	if uuid == "" {
		return nil, fmt.Errorf("empty uuid")
	}
	cachedTrace, existed := ic.getEntry(remoteIP)
	if existed {
		<-cachedTrace.dataReady
		if cachedTrace.err != nil {
			ic.tracetool.DontTrace()
			return nil, cachedTrace.err
		}
		data, err := ic.tracetool.CachedTrace(uuid, time.Now(), cachedTrace.data)
		return data, err
	}
	cachedTrace.data, cachedTrace.err = ic.tracetool.Trace(remoteIP, uuid, cachedTrace.timeStamp)
	close(cachedTrace.dataReady)
	return cachedTrace.data, cachedTrace.err
}

// getEntry returns the entry in the IP cache corresponding to the given
// IP address. If the entry doesn't exist, a new one is created.
func (ic *IPCache) getEntry(ip string) (*cachedTrace, bool) {
	ic.cacheLock.Lock()
	defer ic.cacheLock.Unlock()
	_, existed := ic.cache[ip]
	if !existed {
		ic.cache[ip] = &cachedTrace{
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
