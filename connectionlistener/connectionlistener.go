// Package connectionlistener provides two handlers for open and close
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
	"github.com/m-lab/traceroute-caller/parser"
)

// connectionListener implements the eventsocket.Handler interface, allowing us
// to build a simple client for that service using the libraries from the
// service itself.
type connectionListener struct {
	mutex        sync.Mutex
	conns        map[string]connection.Connection
	ipCache      *ipcache.RecentIPCache
	creator      connection.Creator
	hopAnnotator *hopannotation.HopCache
}

// Open is called when a network connection is opened.
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
func (cl *connectionListener) Close(ctx context.Context, timestamp time.Time, uuid string) {
	cl.mutex.Lock()
	conn, ok := cl.conns[uuid]
	if ok {
		delete(cl.conns, uuid)
		cl.mutex.Unlock()
		go cl.traceAnnotateArchive(ctx, conn, timestamp)
	} else {
		cl.mutex.Unlock()
		log.Printf("failed to find connection for UUID %v", uuid)
	}
}

// traceAnnotateArchive runs a traceroute, takes its output, extracts all tracelb's hop
// IP addresses, annotates the IPs, and writes the annotations to one or more files.
func (cl *connectionListener) traceAnnotateArchive(ctx context.Context, conn connection.Connection, timestamp time.Time) {
	// First, run a traceroute.
	traceOutput, err := cl.ipCache.Trace(conn) // ipcache/ipcachge.go
	if err != nil {
		log.Printf("failed to trace %v (error: %v)", conn.RemoteIP, err)
		return
	}

	// Next, extract tracelb from the output of traceroute and validate it.
	tracelb, err := parser.ExtractTraceLB(traceOutput)
	if err != nil {
		log.Printf("failed to extract tracelb from trace output (error: %v)", err)
		return
	}
	if tracelb.Type != "tracelb" {
		log.Printf("tracelb output has invalid type: %q", tracelb.Type)
		return
	}
	if len(tracelb.Nodes) == 0 {
		log.Printf("tracelb output has no nodes")
		return
	}

	// Now, extract hop IP addresses from tracelb.
	hops := parser.ExtractHops(tracelb)
	if len(hops) == 0 {
		// TODO: Add a histogram metric for hops.
		log.Printf("failed to extract hops from tracelb %+v", tracelb)
		return
	}

	// Finally annotate the new hops and archive.
	n, k, err := cl.hopAnnotator.AnnotateArchive(ctx, hops, timestamp)
	if err != nil {
		log.Printf("failed to annotate and archive %v (n=%v k=%v err=%v)\n", conn.RemoteIP, n, k, err)
	}
}

// New returns an eventsocket.Handler that will call the passed-in scamper
// daemon on every closed connection.
func New(creator connection.Creator, ipCache *ipcache.RecentIPCache, hopAnnotator *hopannotation.HopCache) eventsocket.Handler {
	return &connectionListener{
		conns:        make(map[string]connection.Connection),
		ipCache:      ipCache,
		creator:      creator,
		hopAnnotator: hopAnnotator,
	}
}
