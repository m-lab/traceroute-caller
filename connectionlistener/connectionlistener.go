// Package connectionlistener provides two handlers for open and close
// events called for each network connection.
//
// TODO(SaiedKazemi): The name connectionListener is terribly misleading
//     because this package does not listen on connections! This package
//     should be merged with the package connection into one package.
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

// connectionListener implements the eventsocket.Handler interface, allowing
// us to build a simple client for that service using the libraries from
// the service itself.
// To understand the lifecycle of ipCache, creator, and hopAnnotator see
// ipcache.New(), connection.NewLocalRemoteIPs(), and hopannotation.New()
// respectively.
type connectionListener struct {
	connsLock    sync.Mutex
	conns        map[string]connection.Connection
	ipCache      *ipcache.RecentIPCache
	creator      connection.Creator
	hopAnnotator *hopannotation.HopCache
}

// Open is called when a network connection is opened.
// Note that this function doesn't use timestamp.
func (cl *connectionListener) Open(ctx context.Context, timestamp time.Time, uuid string, sockID *inetdiag.SockID) {
	// TODO(SaiedKazemi): Test code passes nil which makes this
	//     function effectively a no-op. Can sockID ever be nil in
	//     production? Add a metric here.
	if sockID == nil {
		log.Printf("warning: sockID is nil")
		return
	}

	// TODO(SaiedKazemi): Determine whether the lock can be moved
	//     to right before accessing the map.
	cl.connsLock.Lock()
	defer cl.connsLock.Unlock()
	conn, err := cl.creator.FromSockID(*sockID)
	if err != nil {
		log.Printf("failed to create connection from SockID %+v\n", *sockID)
		return
	}
	if uuid == "" {
		// TODO(SaiedKazemi): Add a metric here.
		log.Printf("warning: uuid for SockID %+v is nil\n", *sockID)
	}
	cl.conns[uuid] = conn
}

// Close is called when a network connection is closed.
// Note that this function doesn't use timestamp.
func (cl *connectionListener) Close(ctx context.Context, timestamp time.Time, uuid string) {
	cl.connsLock.Lock()
	conn, ok := cl.conns[uuid]
	if !ok {
		cl.connsLock.Unlock()
		log.Printf("failed to find connection for UUID %v", uuid)
		return
	}

	delete(cl.conns, uuid)
	cl.connsLock.Unlock()
	// Spawn a goroutine to run a traceroute, annotate the hops
	// in the traceroute output, and archive the annotations. This
	// goroutine will live for a few minutes and terminate after all
	// hop annotations are archived.
	go cl.traceAnnotateAndArchive(ctx, conn)
}

func (cl *connectionListener) traceAnnotateAndArchive(ctx context.Context, conn connection.Connection) {
	data, err := cl.ipCache.Trace(conn)
	if err != nil {
		log.Printf("failed to run a trace for connection %v (error: %v)\n", conn, err)
		return
	}
	output, err := parser.ParseTraceroute(data)
	if err != nil {
		log.Printf("failed to parse traceroute output (error: %v)\n", err)
		return
	}
	hops := parser.ExtractHops(&output.Tracelb)
	if len(hops) == 0 {
		log.Printf("failed to extract hops from tracelb %+v\n", output.Tracelb)
		return
	}

	traceStartTime := time.Unix(int64(output.CycleStart.StartTime), 0)
	annotations, allErrs := cl.hopAnnotator.Annotate(ctx, hops, traceStartTime)
	if allErrs != nil {
		log.Printf("failed to annotate some or all hops (errors: %+v)\n", allErrs)
	}
	if annotations != nil && len(annotations) > 0 {
		cl.hopAnnotator.WriteAnnotations(annotations, traceStartTime)
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
