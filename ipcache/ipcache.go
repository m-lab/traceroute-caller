package ipcache

import (
	"context"
	"flag"
	"fmt"
	"sync"
	"time"
)

var (
	// Do not traceroute to an IP more than once in this many seconds
	IPCacheTimeout = flag.Duration("IPCacheTimeout", 120*time.Second, "Timeout duration in seconds for IPCache")

	// Do not traceroute to an IP more than once in this many seconds
	IPCacheUpdateFrequency = flag.Duration("IPCacheUpdateFrequency", 1*time.Second, "We run the cache eviction loop with this frequency")
)

type RecentIPCache struct {
	cache map[string]time.Time
	mu    sync.RWMutex
}

func New(ctx context.Context) *RecentIPCache {
	m := &RecentIPCache{}
	m.mu.Lock()
	m.cache = make(map[string]time.Time)
	m.mu.Unlock()
	go func() {
		ticker := time.NewTicker(*IPCacheUpdateFrequency)
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

func (m *RecentIPCache) Add(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Printf("func Add: Now is %d\n", time.Now().Unix())
	_, ok := m.cache[ip]
	if !ok || m.len() == 0 {
		if len(m.cache) == 0 {
			m.cache = make(map[string]time.Time)
		}
		m.cache[ip] = time.Now()
		fmt.Printf("just add %s %d\n", ip, m.cache[ip].Unix())
	}
}

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
