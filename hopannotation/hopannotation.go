// Package hopannotation handles hop annotation and archiving.
//
// In the context of this package, a hop is synonymous with an IP address.
// This package uses the uuid-annotator (github.com/m-lab/uuid-annotator)
// to annotate hops.  Each hop annotation consists of geolocation and
// Autonomous System Number (ASN) data according to MaxMind, IPinfo.io,
// and RouteViews databases.
//
// Hop annotations are cached for a maximum of one day because the
// annotations can change.  Each hop cache has a cache resetter
// goroutine that resets the cache every day at midnight.
//
// A hop cache entry is an IP address plus the date in yyyymmdd format.
// (e.g., 100.116.79.252-2021-08-26).  The purpose of the date suffix is
// to make sure that hop annotations of a traceroute that ran right before
// midnight do not prevent us from annotating the same hops today.
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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// ErrParseHopIP means a hop IP address could not be parsed.
	ErrParseHopIP = errors.New("failed to parse hop IP address")
	// ErrCreatePath means a directory path for hop annotations could not be created.
	ErrCreatePath = errors.New("failed to create directory path")
	// ErrMarshalAnnotation means a hop annotation could not be marshaled.
	ErrMarshalAnnotation = errors.New("failed to marshal annotation to json")
	// ErrWriteMarshal means a hop annotation could not be written to file.
	ErrWriteMarshal = errors.New("failed to write marshaled annotation")

	hopAnnotationOps = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "hop_cache_operations_total",
			Help: "The number of hop cache operations",
		},
		[]string{"type", "operation"},
	)
	hopAnnotationErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "hop_annotation_errors_total",
			Help: "The number of errors hop annotations errors",
		},
		[]string{"type", "error"},
	)

	hostname string

	// Package testing aid.
	tickerDuration   = int64(60 * 1000 * time.Millisecond) // ticker duration for cache resetter
	writeFile        = ioutil.WriteFile
	errInvalidConfig = errors.New("invalid hop annotation configuration")
)

// HopAnnotation1 is the datatype that is written to the hop annotation file.
type HopAnnotation1 struct {
	ID          string
	Timestamp   time.Time
	Annotations *annotator.ClientAnnotations
}

// Config contains configuration parameters of a hop cache.
// The parameters include the IP service to use and where to save the
// annotations.
type Config struct {
	AnnotatorClient ipservice.Client
	OutputPath      string
}

// HopCache is the cache of hop annotations.
type HopCache struct {
	hops       map[string]bool  // hop addresses being handled or already handled
	hopsLock   sync.Mutex       // hop cache lock
	annotator  ipservice.Client // function for getting hop annotations
	outputPath string           // path to directory for writing hop annotations
	hour       int32            // the hour (between 0 and 23) when cache resetter last checked time
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
// passage of the midnight every minute to reset the cache.  The goroutine
// will terminate when the ctx is cancelled.
func New(ctx context.Context, haCfg Config) (*HopCache, error) {
	if ctx == nil || haCfg.AnnotatorClient == nil || haCfg.OutputPath == "" {
		return nil, fmt.Errorf("%v: %+v", errInvalidConfig, haCfg)
	}
	hc := &HopCache{
		hops:       make(map[string]bool, 10000), // based on observation
		annotator:  haCfg.AnnotatorClient,
		outputPath: haCfg.OutputPath,
	}
	// Start a cache resetter goroutine to reset the cache every day
	// at midnight.  For now, we use atomic read/write operations for
	// hour because package testing code modifies it to fake midnight.
	// Otherwise "go test -race" complains about a race condition.
	// TODO(SaiedKazemi): Use moneky patching to control the progression
	//     of time and get rid of the atomic read.
	go func(duration time.Duration) {
		ticker := time.NewTicker(duration)
		defer ticker.Stop()
		for now := range ticker.C {
			if ctx.Err() != nil {
				return
			}
			hour := now.Hour()
			// Each day, hour increases from 0 to 23.  So if
			// the current hour is less than the previous hour,
			// we must have passed midnight and its' time to
			// reset the hop cache.
			if hour < int(atomic.LoadInt32(&hc.hour)) {
				hc.Reset()
			}
			atomic.StoreInt32(&hc.hour, int32(hour))
		}
	}(time.Duration(tickerDuration))
	return hc, nil
}

// Reset creates a new empty hop cache that is a little bigger (25%)
// than the current cache.  The current cache is retained as old cache
// to allow for active annotations to finish.
func (hc *HopCache) Reset() {
	hc.hopsLock.Lock()
	defer hc.hopsLock.Unlock()
	hc.hops = make(map[string]bool, len(hc.hops)+len(hc.hops)/4)
}

// Annotate annotates new hops found in the hops argument.  It aggregates
// the errors and returns all of them instead of returning after encountering
// the first error.
func (hc *HopCache) Annotate(ctx context.Context, hops []string, traceStartTime time.Time) (map[string]*annotator.ClientAnnotations, []error) {
	if err := ctx.Err(); err != nil {
		return nil, []error{err}
	}

	// Validate all hop IP addresses.
	allErrs := []error{}
	for _, hop := range hops {
		if net.ParseIP(hop).String() == "<nil>" {
			allErrs = append(allErrs, fmt.Errorf("%w: %v", ErrParseHopIP, hop))
		}
	}
	if len(allErrs) != 0 {
		return nil, allErrs
	}

	// Insert all of the new hops in the hop cache.
	// If the cache is reset while iterating this loop, it means that
	// midnight has passed and we have a new empty cache. Therefore,
	// the remaining hops in the hops slice will be inserted in the new
	// cache and added to newHops which is the behavior we want.
	var newHops []string
	yyyymmdd := traceStartTime.Format("-20060102")
	hc.hopsLock.Lock()
	for _, hop := range hops {
		if !hc.hops[hop+yyyymmdd] {
			hopAnnotationOps.WithLabelValues("hopcache", "inserted").Inc()
			hc.hops[hop+yyyymmdd] = true
			newHops = append(newHops, hop)
		}
	}
	hc.hopsLock.Unlock()
	// Are there any new hops?
	if len(newHops) == 0 {
		return nil, nil
	}

	// Annotate the new hops.
	newAnnotations, err := hc.annotator.Annotate(ctx, newHops)
	if err != nil {
		return nil, []error{err}
	}
	hopAnnotationOps.WithLabelValues("hopcache", "annotated").Add(float64(len(newAnnotations)))
	return newAnnotations, nil
}

// WriteAnnotations writes out the annotations passed in.  It writes out the
// annotations in parallel for speed.  It aggregates the errors and returns
// all of them instead of returning after encountering the first error.
func (hc *HopCache) WriteAnnotations(annotations map[string]*annotator.ClientAnnotations, traceStartTime time.Time) []error {
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
		hopAnnotationErrors.WithLabelValues("hopannotation", "marshal").Inc()
		errChan <- fmt.Errorf("%w (error: %v)", ErrMarshalAnnotation, err)
		return
	}
	if err := writeFile(filepath, b, 0444); err != nil {
		hopAnnotationErrors.WithLabelValues("hopannotation", "writefile").Inc()
		errChan <- fmt.Errorf("%w (error: %v)", ErrWriteMarshal, err)
		return
	}
	hopAnnotationOps.WithLabelValues("hopannotation", "written").Inc()
}

// generateAnnotationFilepath returns the full pathname of a hop
// annotation file in the format "<timestamp>_<hostname>_<ip>.json"
func (hc *HopCache) generateAnnotationFilepath(hop string, timestamp time.Time) (string, error) {
	dirPath := hc.outputPath + "/" + timestamp.Format("2006/01/02")
	if err := os.MkdirAll(dirPath, 0777); err != nil {
		hopAnnotationErrors.WithLabelValues("hopannotation", "mkdirall").Inc()
		return "", fmt.Errorf("%w (error: %v)", ErrCreatePath, err)
	}
	datetime := timestamp.Format("20060102T150405Z")
	return fmt.Sprintf("%s/%s_%s_%s.json", dirPath, datetime, hostname, hop), nil
}
