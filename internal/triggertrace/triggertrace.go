// Package triggertrace triggers a traceroute operation to a destination
// after the destination closes its connection with our host (local IP).
// Once a traceroute is obtained, the IP addresses of the hops in that
// traceroute are annotated and archived.
package triggertrace

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/traceroute-caller/hopannotation"
	"github.com/m-lab/traceroute-caller/internal/ipcache"
	"github.com/m-lab/traceroute-caller/parser"
	"github.com/m-lab/uuid-annotator/annotator"
)

var (
	// Variables to aid in black-box testing.
	netInterfaceAddrs = net.InterfaceAddrs
)

// Destination is the host to run a traceroute to.
type Destination struct {
	RemoteIP string
}

// FetchTracer is the interface for obtaining a traceroute.  The
// implementation will return the traceroute from a recent entry in the
// cache (if it exists) in order to avoid running multiple traceroutes to
// the same destination in a short time.
type FetchTracer interface {
	FetchTrace(remoteIP, uuid string) ([]byte, error)
}

// ParseTracer is the interface for parsing raw traceroutes obtained
// from the traceroute tool.
type ParseTracer interface {
	ParseRawData(rawData []byte) (parser.ParsedData, error)
}

// AnnotateAndArchiver is the interface for annotating IP addresses and
// archiving them.
type AnnotateAndArchiver interface {
	Annotate(context.Context, []string, time.Time) (map[string]*annotator.ClientAnnotations, []error)
	WriteAnnotations(map[string]*annotator.ClientAnnotations, time.Time) []error
}

// Handler implements the tcp-info/eventsocket.Handler's interface.
type Handler struct {
	Destinations     map[string]Destination // key is UUID
	DestinationsLock sync.Mutex
	LocalIPs         []*net.IP
	IPCache          FetchTracer
	Parser           ParseTracer
	HopAnnotator     AnnotateAndArchiver
	done             chan struct{} // For testing.
}

// NewHandler returns a new instance of Handler.
func NewHandler(ctx context.Context, tracetool ipcache.Tracer, ipcCfg ipcache.Config, newParser parser.TracerouteParser, haCfg hopannotation.Config) (*Handler, error) {
	ipCache, err := ipcache.New(ctx, tracetool, ipcCfg)
	if err != nil {
		return nil, err
	}
	myIPs, err := localIPs()
	if err != nil {
		return nil, err
	}
	hopCache, err := hopannotation.New(ctx, haCfg)
	if err != nil {
		return nil, err
	}
	return &Handler{
		Destinations: make(map[string]Destination),
		LocalIPs:     myIPs,
		IPCache:      ipCache,
		Parser:       newParser,
		HopAnnotator: hopCache,
	}, nil
}

// Open is called when a network connection is opened.
// Note that this function doesn't use timestamp.
func (h *Handler) Open(ctx context.Context, timestamp time.Time, uuid string, sockID *inetdiag.SockID) {
	if sockID == nil {
		log.Printf("warning: sockID is nil")
		return
	}

	// TODO(SaiedKazemi): Determine whether the lock can be moved
	//     to right before accessing the map.
	h.DestinationsLock.Lock()
	defer h.DestinationsLock.Unlock()
	destination, err := h.findDestination(sockID)
	if err != nil {
		log.Printf("context %p: failed to find destination from SockID %+v\n", ctx, *sockID)
		return
	}
	if uuid == "" {
		// TODO(SaiedKazemi): Add a metric here.
		log.Printf("warning: uuid for SockID %+v is empty\n", *sockID)
	}
	h.Destinations[uuid] = destination
}

// Close is called when a network connection is closed.
// Note that this function doesn't use timestamp.
func (h *Handler) Close(ctx context.Context, timestamp time.Time, uuid string) {
	h.DestinationsLock.Lock()
	destination, ok := h.Destinations[uuid]
	if !ok {
		h.DestinationsLock.Unlock()
		log.Printf("context %p: failed to find destination for UUID %q", ctx, uuid)
		return
	}
	delete(h.Destinations, uuid)
	h.DestinationsLock.Unlock()
	// This goroutine will live for a few minutes and terminate
	// after all hop annotations are archived.
	go h.traceAnnotateAndArchive(ctx, uuid, destination)
}

// traceAnnotateAndArchive runs a traceroute, annotates the hops
// in the traceroute output, and archives the annotations.
func (h *Handler) traceAnnotateAndArchive(ctx context.Context, uuid string, dest Destination) {
	defer func() {
		if h.done != nil {
			close(h.done)
		}
	}()
	rawData, err := h.IPCache.FetchTrace(dest.RemoteIP, uuid)
	if err != nil {
		log.Printf("context %p: failed to run a traceroute to %q (error: %v)\n", ctx, dest, err)
		return
	}
	parsedData, err := h.Parser.ParseRawData(rawData)
	if err != nil {
		log.Printf("context %p: failed to parse traceroute output (error: %v)\n", ctx, err)
		return
	}
	hops := parsedData.ExtractHops()
	if len(hops) == 0 {
		log.Printf("context %p: failed to extract hops from traceroute %+v\n", ctx, string(rawData))
		return
	}

	traceStartTime := parsedData.StartTime()
	annotations, allErrs := h.HopAnnotator.Annotate(ctx, hops, traceStartTime)
	if allErrs != nil {
		log.Printf("context %p: failed to annotate some or all hops (errors: %+v)\n", ctx, allErrs)
	}
	if len(annotations) > 0 {
		allErrs := h.HopAnnotator.WriteAnnotations(annotations, traceStartTime)
		if allErrs != nil {
			log.Printf("context %p: failed to write some or all annotations due to the following error(s):\n", ctx)
			for _, err := range allErrs {
				log.Printf("error: %v\n", err)
			}
		}
	}
}

// findDestination iterates through the local IPs to find which one of
// the source and destination IPs specified in the given socket is indeed
// the destination IP.
func (h *Handler) findDestination(sockid *inetdiag.SockID) (Destination, error) {
	srcIP := net.ParseIP(sockid.SrcIP)
	if srcIP == nil {
		return Destination{}, fmt.Errorf("failed to parse source IP %q", sockid.SrcIP)
	}
	dstIP := net.ParseIP(sockid.DstIP)
	if dstIP == nil {
		return Destination{}, fmt.Errorf("failed to parse destination IP %q", sockid.DstIP)
	}
	srcLocal := false
	dstLocal := false
	for _, localIP := range h.LocalIPs {
		srcLocal = srcLocal || localIP.Equal(srcIP)
		dstLocal = dstLocal || localIP.Equal(dstIP)
	}
	if srcLocal && !dstLocal {
		return Destination{
			RemoteIP: sockid.DstIP,
		}, nil
	}
	if !srcLocal && dstLocal {
		return Destination{
			RemoteIP: sockid.SrcIP,
		}, nil
	}
	return Destination{}, fmt.Errorf("failed to find a local/remote IP pair in %+v", sockid)
}

// localIPs returns the list of system's unicast interface addresses.
func localIPs() ([]*net.IP, error) {
	localIPs := make([]*net.IP, 0)
	addrs, err := netInterfaceAddrs()
	if err != nil {
		return localIPs, err
	}
	for _, addr := range addrs {
		var ip net.IP
		switch a := addr.(type) {
		case *net.IPNet:
			ip = a.IP
		case *net.IPAddr:
			ip = a.IP
		default:
			return localIPs, fmt.Errorf("unknown address type %q", addr.String())
		}
		if ip != nil {
			localIPs = append(localIPs, &ip)
		}
	}
	return localIPs, nil
}
