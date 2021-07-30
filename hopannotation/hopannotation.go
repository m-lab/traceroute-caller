// Package hopannotation handles hop annotation and archiving by
// maintaining a daily cache of annotated and archived hop IP addresses.
//
// TODO: Need to purge the cache at midnight.
package hopannotation

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"cloud.google.com/go/civil"
	"github.com/m-lab/go/rtx"

	// TODO: These should both be in a common location containing API definitions.
	"github.com/m-lab/uuid-annotator/annotator"
	"github.com/m-lab/uuid-annotator/ipservice"
)

// Each hop IP address in the hop cache can be in one of the following
// four states:
//   inserted:  after it's inserted but before annotation
//   annotated: after it's successfully annotated
//   archived:  after it's successfully archived
//   errored:   after encountering an error while archiving
type state int

const (
	inserted state = iota
	annotated
	archived
	errored
)

var (
	// WriteFile is for mocking writing to the filesystem.
	WriteFile = ioutil.WriteFile
	hostname  string
)

// HopAnnotation1 defines the schema for BigQuery hop annotations.
type HopAnnotation1 struct {
	ID   string                       `bigquery:"id"`
	Date civil.Date                   `bigquery:"date"`
	Raw  *annotator.ClientAnnotations `json:",omitempty" bigquery:"raw"`
}

// HopCache implements the cache that handles new hop annotations.
type HopCache struct {
	hops       map[string]state // list of IP addresses already handled
	mu         sync.Mutex       // lock protecting hops
	annotator  ipservice.Client // function for getting hop annotations
	outputPath string           // path to direcotry for writing archives
}

// init saves (caches) the host name for all future references because
// it doesn't change.
func init() {
	var err error
	hostname, err = os.Hostname()
	rtx.Must(err, "failed to get host name")
}

// New returns a new HopCache that will use the provided ipservice.Client
// to obtain annotations.
func New(annotator ipservice.Client, outputPath string) *HopCache {
	return &HopCache{
		hops:       make(map[string]state, 10000), // based on observation
		annotator:  annotator,
		outputPath: outputPath,
	}
}

// Clear removes all entries from the hop cache and creates a new one
// so that reoccurances trigger reprocessing. The new hop cache is a little
// bigger than yesterday.
func (hc *HopCache) Clear() {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	hc.hops = make(map[string]state, len(hc.hops)+len(hc.hops)/4)
}

// AnnotateArchive annotates and archives new hop IP addresses. In case
// of error, it aggregates the errors and returns all of them instead of
// quiting after encountering the first error.
func (hc *HopCache) AnnotateArchive(ctx context.Context, hops []string, timestamp time.Time) (allErrs []error) {
	// Validate all hop IP addresses.
	for _, hop := range hops {
		if net.ParseIP(hop).String() == "<nil>" {
			allErrs = append(allErrs, fmt.Errorf("failed to parse hop IP address: %v", hop))
		}
	}
	if len(allErrs) != 0 {
		return allErrs
	}

	// Get all IP addresses that we haven't seen yet and annotate them.
	newHops := hc.getNewHops(hops)
	if len(newHops) == 0 {
		return allErrs
	}
	// Annotate the new hops and mark them accordingly in the hop cache.
	annotations, err := hc.annotator.Annotate(ctx, newHops)
	if err != nil {
		return append(allErrs, err)
	}
	for hop := range annotations {
		hc.setState(hop, annotated)
	}

	// Archive the new annotations.
	// TODO: Do this in parallel for speed.
	for hop, annotation := range annotations {
		// Get a file path.
		filepath, err := generateAnnotationFilepath(hop, hc.outputPath, timestamp)
		if err != nil {
			allErrs = append(allErrs, err)
			hc.setState(hop, errored)
			continue
		}
		// Write to the file.
		if err := archiveAnnotation(ctx, hop, annotation, filepath, timestamp); err != nil {
			allErrs = append(allErrs, err)
			hc.setState(hop, errored)
		} else {
			hc.setState(hop, archived)
		}
	}
	return allErrs
}

// setState sets the state of the given hop to the given state while
// holding the hop cache lock.
func (hc *HopCache) setState(hop string, hopState state) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	// This sanity checks can be removed once debugging is done.
	var wantState state
	wantOk := true
	gotState, gotOk := hc.hops[hop]
	switch hopState {
	case inserted:
		wantOk = false
	case annotated:
		wantState = inserted
	case archived:
		wantState = annotated
	case errored:
		wantState = annotated
	}
	if gotOk != wantOk || gotState != wantState {
		log.Printf("internal error for hop %v: got %v/%v, want %v/%v", hop, gotState, gotOk, wantState, wantOk)
		log.Printf("setting state for hop %v to %v", hop, hopState)
	}

	hc.hops[hop] = hopState
}

// getNewHops returns the list of new hops that should be annotated
// and archived.
func (hc *HopCache) getNewHops(hops []string) []string {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	// Add new hops to the annotated map and the newHops slice.
	var newHops []string
	for _, hop := range hops {
		if _, ok := hc.hops[hop]; !ok {
			hc.hops[hop] = inserted
			newHops = append(newHops, hop)
		}
	}
	return newHops
}

// generateAnnotationFilepath returns the full pathname of a hop
// annotation file in the format "<timestamp>_<hostname>_<ip>.json"
// TODO: This function should possibly be combined with functions in
//       tracer/tracer.go and put in a packge to be used by both.
func generateAnnotationFilepath(hop, outPath string, timestamp time.Time) (string, error) {
	dirPath := outPath + "/" + timestamp.Format("2006/01/02")
	if err := os.MkdirAll(dirPath, 0777); err != nil {
		// TODO: Add a metric here.
		return "", fmt.Errorf("failed to create directory path (error: %v)", err)
	}
	datetime := timestamp.Format("20060102T150405Z")
	return fmt.Sprintf("%s/%s_%s_%s.json", dirPath, datetime, hostname, hop), nil
}

// archiveAnnotation writes the given hop annotation to a file specified
// by filepath.
func archiveAnnotation(ctx context.Context, hop string, annotation *annotator.ClientAnnotations, filepath string, timestamp time.Time) error {
	yyyymmdd := timestamp.Format("20060102")
	b, err := json.Marshal(HopAnnotation1{
		ID:   fmt.Sprintf("%s_%s_%s", yyyymmdd, hostname, hop),
		Date: civil.DateOf(timestamp),
		Raw:  annotation},
	)
	if err != nil {
		return fmt.Errorf("failed to marshal annotation to json (error: %v)", err)
	}
	if err := WriteFile(filepath, b, 0444); err != nil {
		return fmt.Errorf("failed to write marshaled annotation (error: %v)", err)
	}
	return nil
}
