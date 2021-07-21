// Package hopannotation handles hop annotation and archiving by
// maintaining a daily cache of annotated and archived hop IP addresses.
package hopannotation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"cloud.google.com/go/civil"

	// TODO these should both be in an m-lab/api repository containing only API defs.
	"github.com/m-lab/traceroute-caller/parser"
	"github.com/m-lab/uuid-annotator/annotator"
	"github.com/m-lab/uuid-annotator/ipservice"
)

// HopArchiver is for blackbox package testing.
var HopArchiver = archiveHop

// HopAnnotation1 defines the schema for BigQuery hop annotations.
type HopAnnotation1 struct {
	ID   string                       `bigquery:"id"` // <date>_<machine-site>_<ip>.json
	Date civil.Date                   `bigquery:"date"`
	Raw  *annotator.ClientAnnotations `json:",omitempty" bigquery:"raw"`
}

// HopCache implements the cache that handles new hop annotations.
type HopCache struct {
	annotator  ipservice.Client // function for getting hop annotations
	doneList   map[string]bool  // list of IP addresses already handled
	mu         sync.Mutex       // lock protecting doneList
	outputPath string           // path to direcotry for writing archives
}

// New returns a new HopCache that will use the provided ipservice.Client
// to obtain annotations.
func New(annotator ipservice.Client, outputPath string) *HopCache {
	return &HopCache{
		annotator:  annotator,
		doneList:   make(map[string]bool, 10000), // based on observation
		outputPath: outputPath,
	}
}

// Clear removes all entries from the hop cache and creates a new one
// so that reoccurances trigger reprocessing. The new hop cache is a little
// bigger than yesterday.
func (hc *HopCache) Clear() {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	hc.doneList = make(map[string]bool, len(hc.doneList)+len(hc.doneList)/4)
}

// ProcessHops takes the output of a trace, extracts all tracelb's hop
// IP addresses, annotates, and archives (writes to a file) the annotated
// hop IPs.
func (hc *HopCache) ProcessHops(ctx context.Context, timestamp time.Time, uuid string, traceOutput []byte) (int, int, error) {
	tracelb, err := parser.ExtractTraceLB(traceOutput)
	if err != nil {
		return 0, 0, err
	}
	if tracelb.Type != "tracelb" {
		return 0, 0, fmt.Errorf("tracelb output has invalid type: %v", tracelb.Type)
	}
	if len(tracelb.Nodes) == 0 {
		return 0, 0, fmt.Errorf("no nodes in tracelb output")
	}
	ips, err := parser.ExtractHops(tracelb)
	if err != nil {
		return 0, 0, err
	}
	if len(ips) == 0 {
		return 0, 0, fmt.Errorf("no hop IPs in tracelb output")
	}
	return hc.AnnotateNewHops(ctx, ips, timestamp, uuid)
}

// AnnotateNewHops annotates and archives new hop IP addresses.
// It returns the number of new hops that should have been annotated,
// number actually annotated, and a compound error summarizing any errors
// encountered.
func (hc *HopCache) AnnotateNewHops(ctx context.Context, ips []string, timestamp time.Time, uuid string) (int, int, error) {
	for _, ip := range ips {
		if net.ParseIP(ip) == nil {
			log.Printf("AnnorateNewHops(): invalid IP address ip=%v\n", ip)
			return 0, 0, fmt.Errorf("invalid IP address")
		}
	}
	newHops := hc.getNewHops(ips)

	// Not holding lock
	//     Perform anonymization on hop IPs (eventually - not needed yet).
	//     Request annotations from the annotation service for all new nodes.
	//     annotations is map[string]*annotator.ClientAnnotations
	//
	annotations, err := hc.annotator.Annotate(context.Background(), newHops) // uuid-annotator/ipservice/client.go:Annotate()
	if err != nil {
		log.Printf("failed to annotate hops (error: %v)\n", err)
		return len(newHops), 0, err
	}

	success := 0
	// Create archive records for the new annotations (by calling the generator, possibly in parallel)
	// Aggregate and return errors and counts.
	for ip, annotation := range annotations {
		filename, err := generateFilename(hc.outputPath, timestamp, uuid, ip)
		log.Printf(">>> AnnorateNewHops(): archiving ip=%v annotation in %v\n", ip, filename)
		if err != nil {
			log.Printf("failed to generate filename (error: %v)\n", err)
			return len(newHops), success, err
		}
		if err := HopArchiver(ctx, filename, annotation); err != nil {
			// XXX Returning after the first error (i.e., not aggregating).
			return len(newHops), success, err
		}
		success++
	}
	return len(newHops), success, nil
}

// getNewHops returns the list of new hops that should be annotated and archived.
func (hc *HopCache) getNewHops(ips []string) []string {
	var newHops []string
	hc.mu.Lock()
	defer hc.mu.Unlock()
	// Add new hops to the annotated map and the newHops slice.
	for _, ip := range ips {
		_, ok := hc.doneList[ip]
		if !ok {
			// XXX Isn't marking this as true premature since
			//     we haven't either annotated or archived yet.
			hc.doneList[ip] = true
			newHops = append(newHops, ip)
		}
	}
	return newHops
}

// archiveHop archives the given hop IP. The archive filename should be in the
// "<date>_<machine-site>_<ip>.json" format.
func archiveHop(ctx context.Context, filename string, annotation *annotator.ClientAnnotations) error {
	b, err := json.Marshal(annotation)
	if err != nil {
		log.Printf("failed to marshal annotation to json")
		return err
	}
	err = ioutil.WriteFile(filename, b, 0666)
	if err != nil {
		log.Printf("failed to write marshaled annotation")
	}
	return err
}

// XXX This should be combined with functions in tracer/tracer.go and
// put in a packge to be used by both.
func generateFilename(dirPath string, timestamp time.Time, uuid, ip string) (string, error) {
	dir := dirPath + "/" + timestamp.Format("2006/01/02") + "/"
	if err := os.MkdirAll(dir, 0777); err != nil {
		return "", errors.New("could not create output directory") // TODO add metric here
	}
	return dir + timestamp.Format("20060102T150405Z") + "_" + uuid + "_" + ip + ".json", nil
}
