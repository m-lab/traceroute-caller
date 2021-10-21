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
	"strconv"
	"sync"
	"time"

	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/traceroute-caller/hopannotation"
	"github.com/m-lab/traceroute-caller/ipcache"
	"github.com/m-lab/traceroute-caller/parser"
	"github.com/m-lab/uuid-annotator/annotator"
	"github.com/m-lab/uuid-annotator/ipservice"
)

var (
	netInterfaceAddrs = net.InterfaceAddrs // for black-box testing
)

// Destination is the host to run a traceroute to.
type Destination struct {
	RemoteIP string
	Cookie   string
}

// FetchTracer is the interface for obtaining a traceroute result.
// The implementation can return results from a recent cache in order to
// avoid running multiple traceroutes to the same destination in short time.
type FetchTracer interface {
	FetchTrace(remoteIP, cookie string) ([]byte, error)
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
	Traceroutes      FetchTracer
	HopAnnotator     AnnotateAndArchiver
}

// NewHandler returns a new instance of Handler.
func NewHandler(ctx context.Context, tracer ipcache.Tracer) (*Handler, error) {
	ipCache := ipcache.New(ctx, tracer, 0, 0)
	myIPs, err := localIPs()
	if err != nil {
		return nil, err
	}
	hopCache := hopannotation.New(ctx, ipservice.NewClient(*ipservice.SocketFilename), "")
	return &Handler{
		Destinations: make(map[string]Destination),
		Traceroutes:  ipCache,
		LocalIPs:     myIPs,
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
	destination, err := h.findDestination(*sockID)
	if err != nil {
		log.Printf("failed to create connection from SockID %+v\n", *sockID)
		return
	}
	if uuid == "" {
		// TODO(SaiedKazemi): Add a metric here.
		log.Printf("warning: uuid for SockID %+v is nil\n", *sockID)
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
		log.Printf("failed to find connection for UUID %v", uuid)
		return
	}

	delete(h.Destinations, uuid)
	h.DestinationsLock.Unlock()
	// This goroutine will live for a few minutes and terminate
	// after all hop annotations are archived.
	go h.traceAnnotateAndArchive(ctx, destination)
}

// traceAnnotateAndArchive runs a traceroute, annotates the hops
// in the traceroute output, and archives the annotations.
func (h *Handler) traceAnnotateAndArchive(ctx context.Context, dest Destination) {
	data, err := h.Traceroutes.FetchTrace(dest.RemoteIP, dest.Cookie)
	if err != nil {
		log.Printf("failed to run a trace for connection %v (error: %v)\n", dest, err)
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

	traceStartTime := time.Unix(int64(output.CycleStart.StartTime), 0).UTC()
	annotations, allErrs := h.HopAnnotator.Annotate(ctx, hops, traceStartTime)
	if allErrs != nil {
		log.Printf("failed to annotate some or all hops (errors: %+v)\n", allErrs)
	}
	if len(annotations) > 0 {
		h.HopAnnotator.WriteAnnotations(annotations, traceStartTime)
	}
}

// findDestination iterates through the local IPs to find which one of
// the source and destination IPs specified in the given socket is indeed
// the destination IP.
func (h *Handler) findDestination(sockid inetdiag.SockID) (Destination, error) {
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
	for _, local := range h.LocalIPs {
		srcLocal = srcLocal || local.Equal(srcIP)
		dstLocal = dstLocal || local.Equal(dstIP)
	}
	if srcLocal && !dstLocal {
		return Destination{
			RemoteIP: sockid.DstIP,
			Cookie:   strconv.FormatUint(sockid.CookieUint64(), 16),
		}, nil
	}
	if !srcLocal && dstLocal {
		return Destination{
			RemoteIP: sockid.SrcIP,
			Cookie:   strconv.FormatUint(sockid.CookieUint64(), 16),
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
