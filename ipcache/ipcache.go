// Package ipcache provides a time-based cache object to keep track of recently-seen IP addresses.
package ipcache

import (
	"context"
	"flag"
	"fmt"
	"sync"
	"time"
)

var (
	// IPCacheTimeout sets a lower bound on the amount of time between subsequent traceroutes to a single IP address.
	IPCacheTimeout = flag.Duration("IPCacheTimeout", 120*time.Second, "Timeout duration in seconds for IPCache")

	// IPCacheUpdatePeriod determines how long to wait between cache-scrubbing attempts.
	IPCacheUpdatePeriod = flag.Duration("IPCacheUpdatePeriod", 1*time.Second, "We run the cache eviction loop with this frequency")
)

// RecentIPCache contains a list of all the IP addresses that we have traced to
// recently. We keep this list to ensure that we don't traceroute to the same
// location repeatedly at a high frequency.
type RecentIPCache struct {
	cache map[string]time.Time
	mu    sync.RWMutex
}

// New creates and returns a RecentIPCache. It also starts up a background
// goroutine that scrubs the cache.
func New(ctx context.Context) *RecentIPCache {
	m := &RecentIPCache{}
	m.mu.Lock()
	m.cache = make(map[string]time.Time)
	m.mu.Unlock()
	go func() {
		ticker := time.NewTicker(*IPCacheUpdatePeriod)
		defer ticker.Stop()
		for now := range ticker.C {
			if ctx.Err() != nil {
				return
			}
			for k, v := range m.cache {
				if now.Sub(v) > *IPCacheTimeout {
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

func (m *RecentIPCache) len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.cache)
}

// Add an IP to the cache.
func (m *RecentIPCache) Add(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Printf("func Add: Now is %d\n", time.Now().Unix())
	_, present := m.cache[ip]
	if !present {
		m.cache[ip] = time.Now()
		fmt.Printf("just add %s %d\n", ip, m.cache[ip].Unix())
	}
}

// Has tests whether an IP is in the cache.
func (m *RecentIPCache) Has(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	//fmt.Printf("func Has: Now is %d, length of cache: %d \n", time.Now().Unix(), m.Len())
	if m.len() == 0 {
		return false
	}
	_, ok := m.cache[ip]
	return ok
}
