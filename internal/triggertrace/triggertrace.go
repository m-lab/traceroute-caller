// Package triggertrace triggers a traceroute operation to a destination
// after the destination closes its connection with our host (local IP).
// Once a traceroute is obtained, the IP addresses of the hops in that
// traceroute are annotated and archived.
package triggertrace

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/m-lab/go/anonymize"
	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/traceroute-caller/hopannotation"
	"github.com/m-lab/traceroute-caller/internal/ipcache"
	"github.com/m-lab/traceroute-caller/parser"
	"github.com/m-lab/uuid-annotator/annotator"
)

var (
	// Variables to aid in black-box testing.
	netInterfaceAddrs = net.InterfaceAddrs
	metadataDir       = "/metadata"
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

// TracerWriter provides the interface for issuing traces and writing results.
type TracerWriter interface {
	ipcache.Tracer
	WriteFile(uuid string, t time.Time, b []byte) error
}

// Handler implements the tcp-info/eventsocket.Handler's interface.
type Handler struct {
	Destinations     map[string]Destination // key is UUID
	DestinationsLock sync.Mutex
	LocalIPs         []net.IP
	IPCache          FetchTracer
	Parser           ParseTracer
	HopAnnotator     AnnotateAndArchiver
	Tracetool        TracerWriter
	Anonymizer       anonymize.IPAnonymizer
	done             chan struct{} // For testing.
}

// NewHandler returns a new instance of Handler.
func NewHandler(ctx context.Context, tracetool TracerWriter, ipcCfg ipcache.Config, newParser parser.TracerouteParser, haCfg hopannotation.Config) (*Handler, error) {
	ipCache, err := ipcache.New(ctx, tracetool, ipcCfg)
	if err != nil {
		return nil, err
	}
	myIPs, err := localIPs(metadataDir)
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
		Tracetool:    tracetool,
		Anonymizer:   anonymize.New(anonymize.IPAnonymizationFlag),
	}, nil
}

// Open is called when a network connection is opened.
// Note that this function doesn't use timestamp.
func (h *Handler) Open(ctx context.Context, timestamp time.Time, uuid string, sockID *inetdiag.SockID) {
	if sockID == nil {
		// TODO(SaiedKazemi): Add a metric here.
		log.Printf("error: tcp-info passed a nil sockID\n")
		return
	}
	if uuid == "" {
		// TODO(SaiedKazemi): Add a metric here.
		log.Printf("error: tcp-info passed an empty uuid for sockID %+v\n", *sockID)
		return
	}

	// TODO(SaiedKazemi): Determine whether the lock can be moved
	//     to right before accessing the map.
	h.DestinationsLock.Lock()
	defer h.DestinationsLock.Unlock()
	destination, err := h.findDestination(sockID)
	if err != nil {
		log.Printf("context %p: failed to find destination from SockID %+v: %v\n", ctx, *sockID, err)
		return
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

	// Anonymize the parsed data in place.
	parsedData.Anonymize(h.Anonymizer)
	// Remarshal anonymized data for writing.
	rawData = parsedData.MarshalJSONL()

	traceStartTime := parsedData.StartTime()
	err = h.Tracetool.WriteFile(uuid, traceStartTime, rawData)
	if err != nil {
		log.Printf("context %p: failed to write trace file for uuid: %s: (error: %v)\n", ctx, uuid, err)
	}

	hops := parsedData.ExtractHops()
	if len(hops) == 0 {
		log.Printf("context %p: failed to extract hops from traceroute %+v\n", ctx, string(rawData))
		return
	}
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
func localIPs(metadataDir string) ([]net.IP, error) {
	localIPs := make([]net.IP, 0)
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
			localIPs = append(localIPs, ip)
		}
	}

	localIPs, err = loadbalancerIPs(localIPs, metadataDir)
	if err != nil {
		return localIPs, err
	}

	return localIPs, nil
}

// loadbalancerIPs returns the public IP addresses, if any, of a load balancer
// that may sit in front of the machine. Not all machines site in front of a
// load balancer, so this function may return the the same []*net.IP that was
// passed to it. This function is necessary because traceroute-caller needs to
// recognize the load balancer IPs as "local", else it will fail to identify a
// proper destination, and will exit with an error, producing no traceroute data.
func loadbalancerIPs(localIPs []net.IP, metadataDir string) ([]net.IP, error) {
	var ip net.IP

	// While every machine _should_ have a /metadata/loadbalanced file, for now
	// consider its non-existence to mean that the machine is not load balanced.
	if _, err := os.Stat(metadataDir + "/loadbalanced"); errors.Is(err, os.ErrNotExist) {
		return localIPs, nil
	}

	lb, err := os.ReadFile(metadataDir + "/loadbalanced")
	if err != nil {
		return localIPs, fmt.Errorf("unable to read file %s/loadbalanced: %v", metadataDir, err)
	}

	// If the machine isn't load balanced, then just return localIPs unmodified.
	if string(lb) == "false" {
		return localIPs, nil
	}

	for _, f := range []string{"external-ip", "external-ipv6"} {
		ipBytes, err := os.ReadFile(metadataDir + "/" + f)
		if err != nil {
			return localIPs, fmt.Errorf("unable to read file %s/%s: %v", metadataDir, f, err)
		}
		ipString := string(ipBytes)

		// GCE metadata for key "forwarded-ipv6s" is returned in CIDR format.
		if strings.Contains(ipString, "/") {
			ip, _, _ = net.ParseCIDR(ipString)
		} else {
			ip = net.ParseIP(ipString)
		}
		if ip == nil {
			return localIPs, fmt.Errorf("failed to parse IP: %s", ipString)
		}
		localIPs = append(localIPs, ip)
		log.Printf("added load balancer IP %s to localIPs\n", ip.String())
	}

	return localIPs, nil
}
