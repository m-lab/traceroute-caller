package ipcache

import (
	"fmt"
	"sync"
	"time"
)

// Do not traceroute to an IP more than once in this many seconds
var IP_CACHE_TIME_SECONDS = 120

type RecentIPCache struct {
	cache map[string]int64
	mu    sync.RWMutex
}

func (m *RecentIPCache) New() {
	m.mu.Lock()
	m.cache = make(map[string]int64)
	m.mu.Unlock()
	go func() {
		for now := range time.Tick(time.Second) {

			for k, v := range m.cache {
				if now.Unix()-v > int64(IP_CACHE_TIME_SECONDS) {
					fmt.Println("try to delete " + k)
					m.mu.Lock()
					delete(m.cache, k)
					fmt.Println("delete done")
					m.mu.Unlock()
				}
			}
		}

	}()
	return
}

func (m *RecentIPCache) Flush() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cache = make(map[string]int64)
}

func (m *RecentIPCache) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.cache)
}

func (m *RecentIPCache) Add(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Printf("func Add: Now is %d\n", time.Now().Unix())
	_, ok := m.cache[ip]
	if !ok || m.Len() == 0 {
		if m.cache == nil {
			m.cache = make(map[string]int64)
		}
		m.cache[ip] = time.Now().Unix()
		fmt.Printf("just add %s %d\n", ip, m.cache[ip])
	}
}

func (m *RecentIPCache) Has(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	//fmt.Printf("func Has: Now is %d, length of cache: %d \n", time.Now().Unix(), m.Len())
	if m.Len() == 0 {
		return false
	}
	_, ok := m.cache[ip]
	return ok
}
