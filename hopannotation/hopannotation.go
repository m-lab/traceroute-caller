// Package hopannotation handles hop annotation and archiving by
// maintaining a daily cache of annotated and archived hop IP addresses.
package hopannotation

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/civil"
	"github.com/m-lab/go/rtx"

	// TODO: These should both be in a common location containing API definitions.
	"github.com/m-lab/uuid-annotator/annotator"
	"github.com/m-lab/uuid-annotator/ipservice"
)

var (
	// HopArchiver is for blackbox package testing.
	HopArchiver = archiveHopAnnotation
	hostname    string
	boottime    int64
)

// HopAnnotation1 defines the schema for BigQuery hop annotations.
type HopAnnotation1 struct {
	ID   string                       `bigquery:"id"` // see hopAnnotationFilepath()
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

// init saves (caches) the host name and its boot time for all future
// references because they don't change. They will be used in generating
// the hop annotation file name and ID.
func init() {
	var err error
	hostname, err = os.Hostname()
	rtx.Must(err, "failed to get hostname")

	// TODO: Put the following code (based on "uuid/prefix/prefix.go")
	//       in a package to be used anywhere we need to compute boot time.
	now := time.Now()
	uptimeBytes, err := ioutil.ReadFile("/proc/uptime")
	if err != nil {
		rtx.Must(err, "failed to read /proc/uptime")
	}
	uptimePieces := strings.Split(string(uptimeBytes), " ")
	if len(uptimePieces) < 2 {
		rtx.Must(err, "failed to tokenize /proc/uptime")
	}
	uptimeFloat, err := strconv.ParseFloat(uptimePieces[0], 64)
	if err != nil {
		rtx.Must(err, "failed to parse /proc/uptime")
	}
	boottime = now.Add(-1 * time.Duration(uptimeFloat*1000000) * time.Microsecond).Unix()
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

// AnnotateArchive annotates and archives new hop IP addresses.
// It returns the number of new hops that should have been annotated,
// number actually annotated, and a compound error summarizing any errors
// encountered.
func (hc *HopCache) AnnotateArchive(ctx context.Context, hops []string, timestamp time.Time) (int, int, error) {
	// Validate hops in case our caller hasn't done so.
	for _, hop := range hops {
		if net.ParseIP(hop).String() == "<nil>" {
			return 0, 0, fmt.Errorf("invalid IP address")
		}
	}

	newHops := hc.getNewHops(hops)
	if len(newHops) == 0 {
		log.Printf(">>> AnnotateArchive(): no new hops to annotate len(hops)=%v len(newHops)=%v\n", len(hops), len(newHops))
		return 0, 0, nil
	}

	// Not holding lock
	//     Perform anonymization on hop IPs (eventually - not needed yet).
	//     Request annotations from the annotation service for all new nodes.
	//     annotations is map[string]*annotator.ClientAnnotations
	annotations, err := hc.annotator.Annotate(context.Background(), newHops) // uuid-annotator/ipservice/client.go:Annotate()
	if err != nil {
		log.Printf("failed to annotate hops (error: %v)\n", err)
		return len(newHops), 0, err
	}

	success := 0
	// Create archive records for the new annotations (by calling the generator, possibly in parallel)
	// Aggregate and return errors and counts.
	for hop, annotation := range annotations {
		filepath, err := hopAnnotationFilepath(hop, hc.outputPath, timestamp)
		if err != nil {
			return len(newHops), success, err
		}
		// TODO: Remove the following line after debugging is done.
		log.Printf(">>> AnnotateArchive(): archiving %q annotation in %q\n", hop, filepath)
		if err := HopArchiver(ctx, hop, annotation, filepath, timestamp); err != nil {
			// TODO: Try to annotate all hops and return
			// aggregated errors instead of returning after
			// the first error.
			return len(newHops), success, err
		}
		success++
	}
	return len(newHops), success, nil
}

// getNewHops returns the list of new hops that should be annotated and archived.
func (hc *HopCache) getNewHops(hops []string) []string {
	var newHops []string
	hc.mu.Lock()
	defer hc.mu.Unlock()
	// Add new hops to the annotated map and the newHops slice.
	for _, hop := range hops {
		_, ok := hc.doneList[hop]
		if !ok {
			// TODO: Maintain 3 states: not started, in progress, and done.
			hc.doneList[hop] = true
			newHops = append(newHops, hop)
		}
	}
	log.Printf(">>> getNewHops(): len(hc.doneList)=%v len(hops)=%v len(newHops)=%v", len(hc.doneList), len(hops), len(newHops))
	return newHops
}

// hopAnnotationFilepath returns the full pathname of a hop annotation file
// in the format "<timestamp>_<hostname>_<boottime>_<ip>.json"
func hopAnnotationFilepath(hop, outPath string, timestamp time.Time) (string, error) {
	// TODO: This should possibly be combined with functions in
	//       tracer/tracer.go and put in a packge to be used by both.
	dirPath := outPath + "/" + timestamp.Format("2006/01/02")
	if err := os.MkdirAll(dirPath, 0777); err != nil {
		// TODO: Add a metric here.
		log.Printf("failed to generate directory path (error: %v)\n", err)
		return "", err
	}
	datetime := timestamp.Format("20060102T150405Z")
	return fmt.Sprintf("%s/%s_%s_%d_%s.json", dirPath, datetime, hostname, boottime, hop), nil
}

// archiveHopAnnotation writes the given hop annotation to a file
// specified by filepath.
func archiveHopAnnotation(ctx context.Context, hop string, annotation *annotator.ClientAnnotations, filepath string, timestamp time.Time) error {
	yyyymmdd := timestamp.Format("20060102")
	b, err := json.Marshal(HopAnnotation1{
		ID:   fmt.Sprintf("%s_%s_%d_%s", yyyymmdd, hostname, boottime, hop),
		Date: civil.DateOf(timestamp),
		Raw:  annotation},
	)
	if err != nil {
		log.Printf("failed to marshal annotation to json")
		return err
	}
	err = ioutil.WriteFile(filepath, b, 0666)
	if err != nil {
		log.Printf("failed to write marshaled annotation")
	}
	return err
}
