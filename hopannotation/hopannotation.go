// Package hopannotation handles hop annotation and archiving by
// maintaining a daily cache of annotated and archived hop IP addresses.
//
// This is currently a no-op package so the rest of the code can compile.
package hopannotation

import (
	"context"
	"sync"
	"time"

	"github.com/m-lab/uuid-annotator/annotator"
	"github.com/m-lab/uuid-annotator/ipservice"
)

// Each hop IP address in the hop cache can be in one of the following
// four states:
//   inserted:  after it's inserted but before annotation
//   annotated: after it's successfully annotated
//   archived:  after it's successfully archived
//   errored:   after it has encountered an error while archiving
type entryState int

const (
	inserted entryState = iota
	annotated
	archived
	errored
)

// HopAnnotation1 defines the schema for BigQuery hop annotations.
type HopAnnotation1 struct {
	ID          string
	Timestamp   time.Time
	Annotations *annotator.ClientAnnotations
}

// HopCache implements the cache that handles new hop annotations.
// There may be some annotations in progress when the cache is reset.
// Therefore, Clear() moves hops to oldHops to let active annotations finish
// without causing an internal error (i.e., not finding an annotated hop
// in the cache).
type HopCache struct {
	hops       map[string]entryState // hop addresses being handled or already handled
	oldHops    map[string]entryState // old (currently yesterday's) hops
	hopsLock   sync.Mutex            // hop cache lock
	annotator  ipservice.Client      // function for getting hop annotations
	outputPath string                // path to directory for writing archives
}

// New returns a new HopCache that will use the provided ipservice.Client
// to obtain annotations. The HopCache will be cleared every day at midnight.
func New(ctx context.Context, annotator ipservice.Client, outputPath string) *HopCache {
	return &HopCache{
		hops:       make(map[string]entryState, 10000), // based on observation
		oldHops:    nil,
		annotator:  annotator,
		outputPath: outputPath,
	}
}

// Clear removes all entries from the hop cache and creates a new one
// so that reoccurances trigger reprocessing. The new hop cache is a little
// bigger than yesterday.
func (hc *HopCache) Clear() {
	hc.hops = make(map[string]entryState, len(hc.hops)+len(hc.hops)/4)
}

// AnnotateArchive annotates and archives new hop IP addresses. In case
// of error, it aggregates the errors and returns all of them instead of
// quitting after encountering the first error.
func (hc *HopCache) AnnotateArchive(ctx context.Context, hops []string, traceStartTime time.Time) (allErrs []error) {
	return allErrs
}
