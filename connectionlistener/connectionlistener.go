package connectionlistener

import (
	"log"
	"sync"
	"time"

	"github.com/m-lab/tcp-info/eventsocket"
	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/traceroute-caller/connection"
	"github.com/m-lab/traceroute-caller/ipcache"
	"github.com/m-lab/traceroute-caller/scamper"
)

// connectionListener implements the eventsocket.Handler interface, allowing us
// to build a simple client for that service using the libraries from the
// service itself.
type connectionListener struct {
	mutex   sync.Mutex
	conns   map[string]connection.Connection
	tracer  scamper.Tracer
	cache   *ipcache.RecentIPCache
	creator connection.Creator
}

func (cl *connectionListener) Open(timestamp time.Time, uuid string, id *inetdiag.SockID) {
	cl.mutex.Lock()
	defer cl.mutex.Unlock()
	if id != nil {
		conn, err := cl.creator.FromSockID(*id)
		if err == nil {
			cl.conns[uuid] = conn
		} else {
			log.Printf("Could not create connection from SockID %+v\n", *id)
		}
	}
}

func (cl *connectionListener) Close(timestamp time.Time, uuid string) {
	cl.mutex.Lock()
	conn, ok := cl.conns[uuid]
	if ok {
		delete(cl.conns, uuid)
	}
	cl.mutex.Unlock()

	if ok {
		if !cl.cache.Has(conn.RemoteIP) {
			cl.cache.Add(conn.RemoteIP)
			go cl.tracer.Trace(conn, timestamp)
		}
	}
}

// New returns an eventsocket.Handler that will call the passed-in scamper
// daemon on every closed connection.
func New(tracer scamper.Tracer, creator connection.Creator, cache *ipcache.RecentIPCache) eventsocket.Handler {
	return &connectionListener{
		conns:   make(map[string]connection.Connection),
		tracer:  tracer,
		cache:   cache,
		creator: creator,
	}
}
