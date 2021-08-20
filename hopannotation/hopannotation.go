// Package hopannotation handles hop annotation and archiving by
// maintaining a daily cache of annotated and archived hop IP addresses.
//
// This is currently a stub package so the rest of the code can compile.
package hopannotation

import (
	"context"
	"time"

	"github.com/m-lab/uuid-annotator/ipservice"
)

// HopAnnotation1 is a stub.
type HopAnnotation1 struct{}

// HopCache is a stub.
type HopCache struct{}

// New is a stub.
// to obtain annotations. The HopCache will be cleared every day at midnight.
func New(ctx context.Context, annotator ipservice.Client, outputPath string) *HopCache {
	return &HopCache{}
}

// Clear is a stub.
func (hc *HopCache) Clear() {
}

// AnnotateArchive is a stub.
func (hc *HopCache) AnnotateArchive(ctx context.Context, hops []string, traceStartTime time.Time) (allErrs []error) {
	return allErrs
}
