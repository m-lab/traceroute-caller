// The HopCache is responsible for keeping track of which hops have already
// been annotated (and written to disk), and generating annotations for
// hops that haven't been annotated already (each day)

// TODO decide whether we want this in a package for isolation
package main

import (
	"context"
	"errors"
	"log"
	"sync"

	// TODO these should both be in an m-lab/api repository containing only API defs.
	"github.com/m-lab/uuid-annotator/annotator"
	"github.com/m-lab/uuid-annotator/ipservice"
)

// hopCache implements the cache that handle new hop annotations.
type HopCache struct {
	ann ipservice.Client // function for getting new annotations
	gen HopGenerator     // The function to write archive files

	doneList map[string]bool // list of IP addresses already handled
	mu       sync.Mutex      // lock protecting doneList
}

// HopGenerator defines the function that creates new hop annotation records on disk.
// TODO should this be an interface, rather than a function signature?
type HopGenerator func(context.Context, string, *annotator.ClientAnnotations) error

// New returns a new HopCache that will use the provided ipservice.Client to
// obtain annotations, and generator to create new records.  The injected dependencies
// allow unit testing.
func New(annotator ipservice.Client, generator HopGenerator) *HopCache {
	return &HopCache{
		ann:      annotator,
		gen:      generator,
		doneList: make(map[string]bool, 10000),
	}
}

func (hc *HopCache) Clear() {
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
// Thread-safe!!!
func (hc *HopCache) AnnotateNewHops(ctx context.Context, ips []string) (int, int, error) {
	// Holding lock
	//    add IP keys in the cache for any hops not already in the cache (so that other callers don’t duplicate effort).
	// Not holding lock
	//     Perform anonymization on hop IPs (eventually - not needed yet).
	//     Request annotations from the annotation-service for all new nodes.
	//     Create archive records for the new annotations (by calling the generator, possibly in parallel)
	//     Aggregate and return errors and counts.

	return 0, 0, errors.New("not implemented")
}

// Implementation
// TODO add a test that actually uses this?
func hopGen(ctx context.Context, ip string, ann *annotator.ClientAnnotations) error {
	log.Println("Pretend we wrote a file for", ip)
	return nil
}
