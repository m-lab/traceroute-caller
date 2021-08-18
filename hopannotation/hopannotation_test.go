package hopannotation

import (
	"context"
	"errors"
	"io/fs"
	"sync/atomic"
	"testing"
	"time"

	"github.com/m-lab/uuid-annotator/annotator"
)

var (
	errInvalidIP = errors.New("failed to parse hop IP address: 1.2.3")
	errForced    = errors.New("forced annotate failure")
	errorOnIP    = "0.0.0.0"

	fakeWriteFileCalls int32
)

type fakeAnnotator struct {
	annotateCalls int32
}

func (fa *fakeAnnotator) Annotate(ctx context.Context, hops []string) (map[string]*annotator.ClientAnnotations, error) {
	atomic.AddInt32(&fa.annotateCalls, 1)
	if len(hops) > 0 && hops[0] == errorOnIP {
		return nil, errForced
	}
	m := make(map[string]*annotator.ClientAnnotations)
	for _, hop := range hops {
		m[hop] = &annotator.ClientAnnotations{}
	}
	return m, nil
}

func fakeWriteFile(filename string, data []byte, perm fs.FileMode) error {
	atomic.AddInt32(&fakeWriteFileCalls, 1)
	return nil
}

func TestAnnotateArchive(t *testing.T) {
	// Mock WriteFile.
	saveWriteFile := WriteFile
	WriteFile = fakeWriteFile
	defer func() {
		WriteFile = saveWriteFile
	}()

	tests := []struct {
		hops           []string
		wantAllErrs    []error
		annotateCalls  int32
		writeFileCalls int32
	}{
		{[]string{errorOnIP, errorOnIP}, []error{errForced}, 1, 0}, // we force the first call to Annotate() to fail
		{[]string{"1.2.3.4", "5.6.7.8"}, nil, 2, 2},                // should annotate and archive both
		{[]string{"1.2.3.4", "5.6.7.8"}, nil, 2, 2},                // should not annotate and archive either
		{[]string{"clear-cache", ""}, nil, 0, 0},                   // not a test, just clear the cache
		{[]string{"1.2.3.4", "5.6.7.8"}, nil, 3, 4},                // should annotate and archive both
		{[]string{"5.6.7.8", "a:b:c:d::e"}, nil, 4, 5},             // should annotate and archive just one
		{[]string{"1.2.3"}, []error{errInvalidIP}, 4, 5},           // should return error
	}
	fa := &fakeAnnotator{}
	hc := New(context.TODO(), fa, "./testdata")
	for i, test := range tests {
		if test.hops[0] == "clear-cache" {
			hc.Clear()
			continue
		}

		gotAllErrs := hc.AnnotateArchive(context.TODO(), test.hops, time.Now())

		// Verify that we got the right errors, if any.
		failed := false
		if len(gotAllErrs) != len(test.wantAllErrs) {
			failed = true
		} else {
			for i := range gotAllErrs {
				if gotAllErrs[i].Error() != test.wantAllErrs[i].Error() {
					failed = true
				}
			}
		}
		if failed {
			t.Fatalf("i=%d hc.AnnotateArchive() = %+v, want: %+v", i, gotAllErrs, test.wantAllErrs)
		}

		// Verify the number of Annotate calls.
		if fa.annotateCalls != test.annotateCalls {
			t.Fatalf("i=%d got %d Annotate calls, want %d", i, fa.annotateCalls, test.annotateCalls)
		}

		// Verify the number of WriteFile calls.
		if fakeWriteFileCalls != test.writeFileCalls {
			t.Fatalf("i=%d got %d WriteFile calls, want %d", i, fakeWriteFileCalls, test.writeFileCalls)
		}
	}

	// Now cover the error paths that were not covered by the
	// above tests.
	hc = New(context.TODO(), &fakeAnnotator{}, "/bad/path")
	hc.AnnotateArchive(context.TODO(), []string{"1.1.1.1", "2.2.2.2"}, time.Now())
}

func TestArchiveAnnotation(t *testing.T) {
	annotation := &annotator.ClientAnnotations{
		Geo:     nil,
		Network: nil,
	}
	gotErr := archiveAnnotation(context.TODO(), "1.2.3.4", annotation, "/bad/path", time.Now())
	if gotErr == nil || !errors.Is(gotErr, errWriteMarshal) {
		t.Errorf("archiveAnnotation() = %v, want %v", gotErr, errWriteMarshal)
	}
}

// This is for covering the debug code path in setState().  When debug
// code is removed, this function should also be removed.
func TestSetState(t *testing.T) {
	fa := &fakeAnnotator{}
	hc := New(context.TODO(), fa, "./testdata")
	hc.setState("4.3.2.1", archived) // force error: "does not exist in cache"
	hc.setState("4.3.2.1", archived) // force error: "has state 2, want 1"
}
