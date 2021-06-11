// Package hops contains code related to hop processing.
package hops

import (
	"context"
	"sync"

	// TODO these should both be in an m-lab/api repository containing only API defs.
	"cloud.google.com/go/civil"
	"github.com/m-lab/uuid-annotator/annotator"
	"github.com/m-lab/uuid-annotator/ipservice"
)

// hopCache is responsible for keeping track of which hops have already
// been annotated (and written to disk), and generating annotations for
// hops that haven't been annotated already (each day)

// Cache defines the interface for the hop cache.
// XXX Do we want this interface, or should we just export the struct?
type Cache interface {
	// Clear removes all entries from the cache, so that reoccurances
	// trigger reprocessing.
	Clear()

	// AnnotateNewHops takes a list of IP addresses, and synchronously does whatever
	// is required for each new item in ips.
	// Returns the number of new hops that should have been handles, number
	// actually handled, and a compound error summarizing any errors encountered.
	//
	// NB: May modifies the ips parameter!!
	// Must be thread-safe!!!
	AnnotateNewHops(ctx context.Context, ips []string) (int, int, error)
}

// HopAnnotation1 defines the schema for bigquery hop annotations
// https://docs.google.com/document/d/1Kh-YbJnZhm1KhcPFo-qN48wdpxYpNsrKzNLvKF0_0UI#heading=h.1o8g4cz8a12n
type HopAnnotation1 struct {
	ID   string                       `bigquery:"id"`
	Date civil.Date                   `bigquery:"date"`
	Raw  *annotator.ClientAnnotations `json:",omitempty" bigquery:"raw"`
}

// Hop filename should be <date>_<machine-site>_<ip>.json

// TODO decide whether we want this in a package for isolation
// HopGenerator is the type of the function that creates new hop annotation records.
// TODO should this be an interface, rather than a function signature?
type HopGenerator func(context.Context, string, *annotator.ClientAnnotations) error

// cache implements the cache that handle new hop annotations.
type cache struct {
	ann ipservice.Client // function for getting new annotations
	gen HopGenerator     // The function to write archive files

	doneList map[string]bool // list of IP addresses already handled
	mu       sync.Mutex      // lock protecting doneList
}

// Threadsafe
// Modifies the parameter!
func (hc *cache) todo(ips []string) []string {
	result := ips[:0]
	hc.mu.Lock()
	defer hc.mu.Unlock()
	for i := range ips {
		_, ok := hc.doneList[ips[i]]
		if !ok {
			// Not yet annotated, so add it to both the
			// annotated map, and the todo result slice.
			hc.doneList[ips[i]] = true
			// move it to the result, overwriting original list
			result = append(result, ips[i])
		}
	}
	return result
}

func (hc *cache) Clear() {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	// clear, and make it a little bigger than yesterday.
	hc.doneList = make(map[string]bool, len(hc.doneList)+len(hc.doneList)/4)
}

// AnnotateNewHops takes a list of IP addresses, and synchronously creates new
// archives for any IPs that don’t already exist in the cache.
// Returns the number of new hops that should have been annotated, number
// actually annotated, and a compound error summarizing any errors encountered.
//
// NB: Modifies the ips parameter!!
// Thread-safe!!!
func (hc *cache) AnnotateNewHops(ctx context.Context, ips []string) (int, int, error) {
	todo := hc.todo(ips) // modifies the original ips slice that was passed in!

	// Not holding lock
	//     Perform anonymization on hop IPs (eventually - not needed yet).
	//     Request annotations from the annotation-service for all new nodes.
	annotations, err := hc.ann.Annotate(ctx, todo)
	if err != nil {
		return 0, 0, err
	}

	success := 0
	fail := 0
	//     Create archive records for the new annotations (by calling the generator, possibly in parallel)
	//     Aggregate and return errors and counts.
	for ip, ann := range annotations {
		err := hc.gen(ctx, ip, ann)
		if err == nil {
			success++
		} else {
			fail++
		}
	}

	return len(todo), success, nil
}

// New returns a new HopCache that will use the provided ipservice.Client to
// obtain annotations, and generator to create new records.  The injected dependencies
// allow unit testing.
func New(annotator ipservice.Client, generator HopGenerator) Cache {
	return &cache{
		ann:      annotator,
		gen:      generator,
		doneList: make(map[string]bool, 10000),
	}
}
