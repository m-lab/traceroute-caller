// package cache implements a general purpose cache
package cache

import (
	"errors"
	"sync"
	"time"

	"github.com/m-lab/traceroute-caller/connection"
	"github.com/m-lab/traceroute-caller/ipcache"
)

type Entry interface {
	Populate(data []byte, err error) error
	Value() (data []byte, err error) // Blocks until ready
}

// An item in the cache must track a few different conditions
type item struct {
	expiryTime time.Time     // The expiration time of this entry.
	data       []byte        // The cached data.  May be nil.
	ready      chan struct{} // Indicates that the item has been populated or action completed (or errored).
	err        error         // Indicates that an error occurred when populating the item.
}

var ErrAlreadyPopulated = errors.New("item already populated")

// Populate populates the content of a previously created item.
func (v *item) Populate(data []byte, err error) error {
	select {
	case <-v.ready: // already closed
		return ErrAlreadyPopulated
	default:
		v.data = data
		v.err = err
		close(v.ready)
	}
	return nil
}

// Value blocks until the item value is ready, then returns the data and error values.
func (v *item) Value() ([]byte, error) {
	<-v.ready
	return v.data, v.err
}

// The PendingCache itself contains the map from key to items, the expiration interval (may be 0 if no expiration).
type PendingCache struct {
	values         map[string]*item
	expiryInterval time.Duration
	mu             sync.Mutex
}

// gets an entry, or creates a pending entry if no entry exists
func (c *PendingCache) Get(key string) (Entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, existed := c.values[key]
	if !existed {
		e = &item{
			expiryTime: time.Now().Add(c.expiryInterval),
			ready:      make(chan struct{}),
		}
		c.values[key] = e
	}
	return e, existed
}

// Example use for IP cache.
type RecentIPCache struct {
	PendingCache

	tracer ipcache.Tracer
}

func (rc *RecentIPCache) getEntry(ip string) (Entry, bool) {
	return rc.PendingCache.Get(ip)
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
	e, cached := rc.Get(conn.RemoteIP)
	if !cached {
		data, err := t.Trace(conn, time.Now())
		e.Populate(data, err)
	}
	data, err := e.Value()
	if err == nil {
		_ = t.TraceFromCachedTrace(conn, time.Now(), data)
		return data, nil
	}
	t.DontTrace(conn, err)
	return nil, err
}
