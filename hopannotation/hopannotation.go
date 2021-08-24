// Package hopannotation handles hop annotation and archiving.
//
// In the context of this package, a hop is synonymous with an IP address.
// This package uses the uuid-annotator (github.com/m-lab/uuid-annotator)
// to annotate hops.  Each hop annotation consists of geolocation and
// Autonomous System Number (ASN) data according to MaxMind, IPinfo.io,
// and RouteViews databases.
//
// Hop annotations are cached for a maximum of one day because the
// annotations can change.  Each hop cache has a cache clearer
// goroutine that clears the cache every day at midnight.
//
// This package has the following exported functions:
//   New()
//   (*HopCache) Clear()
//   (*HopCache) Annotate()
//   (*HopCache) WriteAnnotations()
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
	"sync/atomic"
	"time"

	// TODO: These should both be in a common location containing API definitions.
	"github.com/m-lab/uuid-annotator/annotator"
	"github.com/m-lab/uuid-annotator/ipservice"
)

// Each hop in the hop cache can be in one of the following four states:
//   inserted:  after it's inserted but before it is annotated
//   annotated: after it's successfully annotated
//   written:  after it's successfully written
//   errored:   after encountering an error while archiving
type entryState int

const (
	inserted entryState = iota
	annotated
	written
	errored
	numStates
)

var (
	errParseHopIP        = errors.New("failed to parse hop IP address")
	errCreatePath        = errors.New("failed to create directory path")
	errMarshalAnnotation = errors.New("failed to marshal annotation to json")
	errWriteMarshal      = errors.New("failed to write marshaled annotation")

	hostname string

	// Package testing aid.
	tickerDuration = int32(60 * 1000) // ticker duration in milliseconds for cache clearer
	writeFile      = ioutil.WriteFile
)

// HopAnnotation1 is the datatype that is written to the hop annotation file.
type HopAnnotation1 struct {
	ID          string
	Timestamp   time.Time
	Annotations *annotator.ClientAnnotations
}

// HopCache is the cache of hop annotations.
type HopCache struct {
	hops       map[string]entryState // hop addresses being handled or already handled
	oldHops    map[string]entryState // old (yesterday's) hops
	hopsLock   sync.Mutex            // hop cache lock
	annotator  ipservice.Client      // function for getting hop annotations
	outputPath string                // path to directory for writing hop annotations
	hour       int32                 // the hour when cache clearer last checked time
}

// init saves (caches) the host name for all future references because
// the host name doesn't change.
func init() {
	var err error
	hostname, err = os.Hostname()
	if err != nil {
		log.Fatalf("failed to get hostname (error: %v)\n", err)
	}
}

// New returns a new HopCache that will use the provided ipservice.Client
// to obtain annotations.  It also starts a goroutine that checks for the
// passage of the midnight every minute to clear the cache.  The goroutine
// will terminate when the ctx is cancelled.
func New(ctx context.Context, annotator ipservice.Client, outputPath string) *HopCache {
	hc := &HopCache{
		hops:       make(map[string]entryState, 10000), // based on observation
		oldHops:    nil,
		annotator:  annotator,
		outputPath: outputPath,
	}
	// Start a cache clearer goroutine to clear the cache every day
	// at midnight.  Read tickerDuration and hour atomically to avoid
	// a race condition with package testing code.
	go func() {
		d := time.Duration(atomic.LoadInt32(&tickerDuration))
		ticker := time.NewTicker(d * time.Millisecond)
		defer ticker.Stop()
		for now := range ticker.C {
			if ctx.Err() != nil {
				return
			}
			hour := now.Hour()
			if hour < int(atomic.LoadInt32(&hc.hour)) {
				hc.Clear()
			}
			atomic.StoreInt32(&hc.hour, int32(hour))
		}
	}()
	return hc
}

// Clear creates a new empty hop cache that is a little bigger (25%)
// than the current cache.  The current cache is retained as old cache
// to allow for active annotations to finish.
func (hc *HopCache) Clear() {
	hc.hopsLock.Lock()
	defer hc.hopsLock.Unlock()
	// Verify that all hops in the old cache are written.
	var hopStates [numStates]entryState
	for _, hopState := range hc.oldHops {
		hopStates[hopState]++
	}
	if hopStates[inserted] != 0 || hopStates[annotated] != 0 || hopStates[errored] != 0 {
		log.Printf("warning: there were unwritten entries in the old cache (%+v)\n", hopStates)
	}
	hc.oldHops = hc.hops
	hc.hops = make(map[string]entryState, len(hc.hops)+len(hc.hops)/4)
}

// Annotate annotates new hops found in the hops argument.  It aggregates
// the errors and returns all of them instead of returning after encountering
// the first error.
func (hc *HopCache) Annotate(ctx context.Context, hops []string) (map[string]*annotator.ClientAnnotations, []error) {
	if err := ctx.Err(); err != nil {
		return nil, []error{err}
	}

	// Validate all hop IP addresses.
	allErrs := []error{}
	for _, hop := range hops {
		if net.ParseIP(hop).String() == "<nil>" {
			allErrs = append(allErrs, fmt.Errorf("%w: %v", errParseHopIP, hop))
		}
	}
	if len(allErrs) != 0 {
		return nil, allErrs
	}

	// Insert all of the new hops in the hop cache and mark them
	// as inserted.
	var newHops []string
	for _, hop := range hops {
		hc.hopsLock.Lock()
		if _, ok := hc.hops[hop]; !ok {
			hc.hops[hop] = inserted
			newHops = append(newHops, hop)
		}
		hc.hopsLock.Unlock()
	}
	// Are there any new hops?
	if len(newHops) == 0 {
		return nil, nil
	}

	// Annotate the new hops and mark them as annotated.
	newAnnotations, err := hc.annotator.Annotate(ctx, newHops)
	if err != nil {
		return nil, []error{err}
	}
	for hop := range newAnnotations {
		hc.setState(hop, annotated)
	}
	return newAnnotations, nil
}

// WriteAnnotations writes out the annotations passed in.  It writes out the
// annotations in parallel for speed.  It aggregates the errors and returns
// all of them instead of returning after encountering the first error.
func (hc *HopCache) WriteAnnotations(ctx context.Context, annotations map[string]*annotator.ClientAnnotations, traceStartTime time.Time) []error {
	if err := ctx.Err(); err != nil {
		return []error{err}
	}

	// Write the annotations in parallel.
	var wg sync.WaitGroup
	errChan := make(chan error, len(annotations))
	for hop, annotation := range annotations {
		wg.Add(1)
		go hc.writeAnnotation(&wg, hop, annotation, traceStartTime, errChan)
	}
	wg.Wait()
	close(errChan)
	var allErrs []error
	for err := range errChan {
		allErrs = append(allErrs, err)
	}
	return allErrs
}

// writeAnnotation writes the given hop annotations to a file.
func (hc *HopCache) writeAnnotation(wg *sync.WaitGroup, hop string, annotation *annotator.ClientAnnotations, traceStartTime time.Time, errChan chan<- error) {
	defer wg.Done()

	// Get a file path.
	filepath, err := hc.generateAnnotationFilepath(hop, traceStartTime)
	if err != nil {
		hc.setState(hop, errored)
		errChan <- err
		return
	}

	// Write to the file.
	yyyymmdd := traceStartTime.Format("20060102")
	b, err := json.Marshal(HopAnnotation1{
		ID:          fmt.Sprintf("%s_%s_%s", yyyymmdd, hostname, hop),
		Timestamp:   traceStartTime,
		Annotations: annotation,
	})
	if err != nil {
		hc.setState(hop, errored)
		errChan <- fmt.Errorf("%w (error: %v)", errMarshalAnnotation, err)
		return
	}
	if err := writeFile(filepath, b, 0444); err != nil {
		hc.setState(hop, errored)
		errChan <- fmt.Errorf("%w (error: %v)", errWriteMarshal, err)
		return
	}

	// Mark the cache entry as written.
	hc.setState(hop, written)
}

// setState sets the state of the given hop entry in the cache to the
// given state while holding the hop cache lock.
func (hc *HopCache) setState(hop string, hopState entryState) {
	var wantState entryState
	switch hopState {
	case annotated:
		wantState = inserted
	case written:
		wantState = annotated
	case errored:
		wantState = annotated
	}

	// Lock the hop cache.
	hc.hopsLock.Lock()
	defer hc.hopsLock.Unlock()

	// Find the hop entry in the cache.
	old := false
	state, ok := hc.hops[hop]
	if !ok {
		// Check the old cache.
		state, ok = hc.oldHops[hop]
		if !ok {
			log.Printf("internal error: hop %v does not exist in cache", hop)
			state = wantState
		} else {
			old = true
		}
	}
	// Do a sanity check.
	if state != wantState {
		log.Printf("internal error: hop %v has state %v, want %v (setting to %v)", hop, state, wantState, wantState)
	}

	// Set the state.
	if old {
		hc.oldHops[hop] = hopState
	} else {
		hc.hops[hop] = hopState
	}
}

// generateAnnotationFilepath returns the full pathname of a hop
// annotation file in the format "<timestamp>_<hostname>_<ip>.json"
func (hc *HopCache) generateAnnotationFilepath(hop string, timestamp time.Time) (string, error) {
	dirPath := hc.outputPath + "/" + timestamp.Format("2006/01/02")
	if err := os.MkdirAll(dirPath, 0777); err != nil {
		// TODO(SaiedKazemi): Add a metric here.
		return "", fmt.Errorf("%w (error: %v)", errCreatePath, err)
	}
	datetime := timestamp.Format("20060102T150405Z")
	return fmt.Sprintf("%s/%s_%s_%s.json", dirPath, datetime, hostname, hop), nil
}
