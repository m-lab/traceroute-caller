package connectionlistener

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/m-lab/tcp-info/eventsocket"
	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/traceroute-caller/connection"
	"github.com/m-lab/traceroute-caller/ipcache"
	"github.com/m-lab/traceroute-caller/parser"
)

// connectionListener implements the eventsocket.Handler interface, allowing us
// to build a simple client for that service using the libraries from the
// service itself.
type connectionListener struct {
	mutex   sync.Mutex
	conns   map[string]connection.Connection
	cache   *ipcache.RecentIPCache
	creator connection.Creator
}

func (cl *connectionListener) Open(ctx context.Context, timestamp time.Time, uuid string, id *inetdiag.SockID) {
	cl.mutex.Lock()
	defer cl.mutex.Unlock()
	if id != nil {
		conn, err := cl.creator.FromSockID(*id)
		if err == nil {
			cl.conns[uuid] = conn
		} else {
			log.Printf("failed to create connection from SockID %+v\n", *id)
		}
	}
}

func (cl *connectionListener) Close(ctx context.Context, timestamp time.Time, uuid string) {
	cl.mutex.Lock()
	conn, ok := cl.conns[uuid]
	if ok {
		delete(cl.conns, uuid)
	}
	cl.mutex.Unlock()

	if ok {
		go func() {
			data, err := cl.cache.Trace(conn)
			if err != nil {
				log.Printf("failed to run a trace for connection %v (error: %v)\n", conn, err)
			} else {
				if _, err := parser.ParseTraceroute(data); err != nil {
					log.Printf("failed to parse traceroute output (error: %v)\n", err)
				} else {
					// TODO: Remove this line when done debugging.
					log.Printf("successfully parsed traceroute output\n")
				}
			}
		}()
	}
}

// New returns an eventsocket.Handler that will call the passed-in scamper
// daemon on every closed connection.
func New(creator connection.Creator, cache *ipcache.RecentIPCache) eventsocket.Handler {
	return &connectionListener{
		conns:   make(map[string]connection.Connection),
		cache:   cache,
		creator: creator,
	}
}
