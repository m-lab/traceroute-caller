// package cache implements a general purpose cache
package cache

import (
	"sync"
	"time"

	"github.com/m-lab/traceroute-caller/connection"
	"github.com/m-lab/traceroute-caller/ipcache"
)

// The cache stores key value pair, and will execute an arbitrary function to
// fill an entry if one does not exist.

type prompt interface {
	key() string
}

type cacheable struct {
	prompt interface{} // pointer to a custom struct containing whatever is needed

}

type item struct {
	expiry time.Time
	data   []byte
	ready  chan struct{}
	err    error
}

type cache struct {
	values map[string]*item
	expiry time.Duration
	mu     sync.Mutex
}

type fetchFunc func(string) ([]byte, error)

func (c *cache) get(key string, f fetchFunc) ([]byte, error) {
	e, cached := c.getEntry(key)
	if cached {
		<-e.ready
	} else {
		e.data, e.err = f(key)
		close(e.ready)
	}
	return e.data, e.err
}

// gets an entry, or creates a pending entry if no entry exists
func (c *cache) getEntry(key string) (*item, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, existed := c.values[key]
	if !existed {
		e = &item{
			expiry: time.Now().Add(c.expiry),
			ready:  make(chan struct{}),
		}
		c.values[key] = e
	}
	return e, existed
}

type RecentIPCache struct {
	cache

	tracer ipcache.Tracer
}

func (rc *RecentIPCache) getEntry(ip string) (*item, bool) {
	return rc.cache.getEntry(ip)
}

func (rc *RecentIPCache) getTracer() ipcache.Tracer {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.tracer
}

// Trace performs a trace and adds it to the cache. It calls the methods of the
// tracer, so if those create files on disk, then files on disk will be created
// as a side effect.
func (rc *RecentIPCache) Trace(conn connection.Connection) ([]byte, error) {
	t := rc.getTracer()
	f := func(string) ([]byte, error) {
		return t.Trace(conn, time.Now())
	}
	c, err := rc.get(conn.RemoteIP, f)
	if err != nil {
		return nil, err
	}
	if cached {
		<-c.ready
		if c.err == nil {
			_ = t.TraceFromCachedTrace(conn, time.Now(), c.data)
			return c.data, nil
		}
		t.DontTrace(conn, c.err)
		return nil, c.err
	}
	c.data, c.err = t.Trace(conn, time.Now())
	close(c.ready)
	return c.data, c.err
}
