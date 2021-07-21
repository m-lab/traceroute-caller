// Package connectionlistener provides two handles for open and close
// events called for each network connection.
//
// XXX The name connectionListener is terribly misleading because this
//     package does not listen on connections!  Rather, it just has two
//     handlers for open and close events, called as callback functions
//     by the tcp-info/eventsocket package.
package connectionlistener

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/m-lab/tcp-info/eventsocket"
	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/traceroute-caller/connection"
	"github.com/m-lab/traceroute-caller/hopannotation"
	"github.com/m-lab/traceroute-caller/ipcache"
)

// connectionListener implements the eventsocket.Handler interface, allowing us
// to build a simple client for that service using the libraries from the
// service itself.
type connectionListener struct {
	mutex    sync.Mutex
	conns    map[string]connection.Connection
	ipCache  *ipcache.RecentIPCache
	creator  connection.Creator
	hopCache *hopannotation.HopCache
}

// Open is called when a network connection is opened.
// XXX This function should return error instead of ignoring it
//     and let the caller decide to ignore or handle errors.
func (cl *connectionListener) Open(ctx context.Context, timestamp time.Time, uuid string, id *inetdiag.SockID) {
	// XXX If id is nil, this just eats up CPU cycles.
	//     Shouldn't this function keep track of no-ops?
	cl.mutex.Lock()
	defer cl.mutex.Unlock()
	if id != nil {
		conn, err := cl.creator.FromSockID(*id)
		if err != nil {
			log.Printf("Could not create connection from SockID %+v\n", *id)
			return
		}
		cl.conns[uuid] = conn // XXX Are we guaranteed uuid is never empty (i.e., "")?
	}
}

// Close is called when a network connection is closed.
// XXX This function should return error instead of ignoring it
//     and let the caller decide to ignore or handle errors.
func (cl *connectionListener) Close(ctx context.Context, timestamp time.Time, uuid string) {
	cl.mutex.Lock()
	conn, ok := cl.conns[uuid]
	if ok {
		delete(cl.conns, uuid) // XXX Why should we delete the entry?
	}
	cl.mutex.Unlock()
	if !ok {
		log.Printf("failed to find connection for UUID %v", uuid)
		return
	}

	go func() {
		traceOutput, err := cl.ipCache.Trace(conn) // ipcache/ipcachge.go
		if err != nil {
			log.Printf("failed to trace %v", conn.RemoteIP)
			return
		}
		n, k, err := cl.hopCache.ProcessHops(ctx, timestamp, uuid, traceOutput) // hopannotation/hopannotation.go
		if err != nil {
			log.Printf("failed to annotate and archive %v (n=%v k=%v err=%v)\n", conn.RemoteIP, n, k, err)
		}
	}()
}

// New returns an eventsocket.Handler that will call the passed-in scamper
// daemon on every closed connection.
func New(creator connection.Creator, ipCache *ipcache.RecentIPCache, hopCache *hopannotation.HopCache) eventsocket.Handler {
	return &connectionListener{
		conns:    make(map[string]connection.Connection),
		ipCache:  ipCache,
		creator:  creator,
		hopCache: hopCache,
	}
}
