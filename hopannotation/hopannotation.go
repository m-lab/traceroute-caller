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
type entryState int

const (
	inserted entryState = iota
	annotated
	archived
	errored
)

var (
	errParseHopIP        = errors.New("failed to parse hop IP address")
	errCreatePath        = errors.New("failed to create directory path")
	errMarshalAnnotation = errors.New("failed to marshal annotation to json")
	errWriteMarshal      = errors.New("failed to write marshaled annotation")

	// WriteFile is for mocking writing to the filesystem.
	WriteFile = ioutil.WriteFile
	hostname  string
)

// HopAnnotation1 defines the schema for BigQuery hop annotations.
type HopAnnotation1 struct {
	ID          string
	Timestamp   time.Time
	Annotations *annotator.ClientAnnotations
}

// HopCache implements the cache that handles new hop annotations.
type HopCache struct {
	hops       map[string]entryState // hop addresses being handled or already handled
	oldHops    map[string]entryState // old (yesterday's) hops
	hopsLock   sync.Mutex            // hop cache lock
	annotator  ipservice.Client      // function for getting hop annotations
	outputPath string                // path to directory for writing archives
}

// init saves (caches) the host name for all future references because
// it doesn't change.
func init() {
	var err error
	hostname, err = os.Hostname()
	rtx.Must(err, "failed to get host name")
}

// New returns a new HopCache that will use the provided ipservice.Client
// to obtain annotations. The HopCache will be cleared every day at midnight.
func New(ctx context.Context, annotator ipservice.Client, outputPath string) *HopCache {
	hc := &HopCache{
		hops:       make(map[string]entryState, 10000), // based on observation
		oldHops:    nil,
		annotator:  annotator,
		outputPath: outputPath,
	}
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		prevHour := time.Now().Hour()
		for now := range ticker.C {
			if ctx.Err() != nil {
				return
			}
			// Did we pass midnight?
			if now.Hour() < prevHour {
				hc.Clear()
				prevHour = now.Hour()
			}
		}
	}()
	return hc
}

// Clear removes all entries from the hop cache and creates a new one
// so that reoccurances trigger reprocessing. The new hop cache is a little
// bigger than yesterday.
func (hc *HopCache) Clear() {
	hc.hopsLock.Lock()
	defer hc.hopsLock.Unlock()
	oldHopsDone := true
	for _, v := range hc.oldHops {
		if v != archived && v != errored {
			oldHopsDone = false
			break
		}
	}
	if oldHopsDone {
		hc.oldHops = hc.hops
	}
	hc.hops = make(map[string]entryState, len(hc.hops)+len(hc.hops)/4)
}

// AnnotateArchive annotates and archives new hop IP addresses. In case
// of error, it aggregates the errors and returns all of them instead of
// quitting after encountering the first error.
func (hc *HopCache) AnnotateArchive(ctx context.Context, hops []string, traceStartTime time.Time) (allErrs []error) {
	// Validate all hop IP addresses.
	for _, hop := range hops {
		if net.ParseIP(hop).String() == "<nil>" {
			allErrs = append(allErrs, fmt.Errorf("%w: %v", errParseHopIP, hop))
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
		filepath, err := generateAnnotationFilepath(hop, hc.outputPath, traceStartTime)
		if err != nil {
			allErrs = append(allErrs, err)
			hc.setState(hop, errored)
			continue
		}
		// Write to the file.
		if err := archiveAnnotation(ctx, hop, annotation, filepath, traceStartTime); err != nil {
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
func (hc *HopCache) setState(hop string, hopState entryState) {
	var wantState entryState
	switch hopState {
	case annotated:
		wantState = inserted
	case archived:
		wantState = annotated
	case errored:
		wantState = annotated
	}

	// Lock the hop cache.
	hc.hopsLock.Lock()
	defer hc.hopsLock.Unlock()

	old := false
	state, ok := hc.hops[hop]
	if !ok {
		// Check the old list.
		state, ok = hc.oldHops[hop]
		if !ok {
			log.Printf("internal error: hop %v does not exist in cache", hop)
			state = wantState
		} else {
			old = true
		}
	}
	// Sanity check.
	if state != wantState {
		log.Printf("internal error: hop %v has state %v, want %v", hop, state, wantState)
		log.Printf("recovering by setting state for hop %v to %v", hop, hopState)
	}

	if old {
		hc.oldHops[hop] = hopState
	} else {
		hc.hops[hop] = hopState
	}
}

// getNewHops returns the list of new hops that should be annotated
// and archived.
func (hc *HopCache) getNewHops(hops []string) []string {
	hc.hopsLock.Lock()
	defer hc.hopsLock.Unlock()

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
//       tracer/tracer.go and put in a package to be used by both.
func generateAnnotationFilepath(hop, outPath string, timestamp time.Time) (string, error) {
	dirPath := outPath + "/" + timestamp.Format("2006/01/02")
	if err := os.MkdirAll(dirPath, 0777); err != nil {
		// TODO: Add a metric here.
		return "", fmt.Errorf("%w (error: %v)", errCreatePath, err)
	}
	datetime := timestamp.Format("20060102T150405Z")
	return fmt.Sprintf("%s/%s_%s_%s.json", dirPath, datetime, hostname, hop), nil
}

// archiveAnnotation writes the given hop annotation to a file specified
// by filepath.
func archiveAnnotation(ctx context.Context, hop string, annotation *annotator.ClientAnnotations, filepath string, traceStartTime time.Time) error {
	yyyymmdd := traceStartTime.Format("20060102")
	b, err := json.Marshal(HopAnnotation1{
		ID:          fmt.Sprintf("%s_%s_%s", yyyymmdd, hostname, hop),
		Timestamp:   traceStartTime,
		Annotations: annotation,
	})
	if err != nil {
		return fmt.Errorf("%w (error: %v)", errMarshalAnnotation, err)
	}
	if err := WriteFile(filepath, b, 0444); err != nil {
		return fmt.Errorf("%w (error: %v)", errWriteMarshal, err)
	}
	return nil
}
