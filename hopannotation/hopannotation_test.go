package hopannotation

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/m-lab/uuid-annotator/annotator"
)

var (
	errInvalidIP = errors.New("failed to parse hop IP address: 1.2.3")
	errForced    = errors.New("forced failure")
	errorOnIP    = "0.0.0.0"

	fakeWriteFileCalls int32

	tests = []struct {
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

func fakeWriteFile(filepath string, data []byte, perm fs.FileMode) error {
	atomic.AddInt32(&fakeWriteFileCalls, 1)
	// Force a failure on one of the files for code coverage of
	// error path.
	if strings.Contains(filepath, "a:b:c:d::e") {
		return errForced
	}
	return nil
}

func TestNew(t *testing.T) {
	// Change ticker duration to 100ms to avoid waiting a long time for
	// the clearer goroutine to notice passage of midnight or cancelled
	// context.
	saveTickerIntvl := atomic.SwapInt32(&tickerDuration, 100)
	defer func() {
		atomic.StoreInt32(&tickerDuration, saveTickerIntvl)
	}()

	// Create a new hop cache and insert an entry in it.
	ctx, cancel := context.WithCancel(context.Background())
	hc := New(ctx, &fakeAnnotator{}, "./testdata")
	hc.hopsLock.Lock()
	hc.hops["1.2.3.4"] = true
	hc.hopsLock.Unlock()

	// Fake we've reached midnight and verify that our current cache
	// has become the old cache and the new cache is empty.
	fakeMidnight(hc)
	hc.hopsLock.Lock()
	if len(hc.hops) != 0 {
		t.Fatal("failed to clear cache at midnight")
	}
	hc.hopsLock.Unlock()

	// Cancel the context and verify the clearer goroutine has stopped.
	cancel()
	fakeMidnight(hc)
	if atomic.LoadInt32(&hc.hour) != 24+1 {
		t.Fatal("failed to stop the clearer goroutine")
	}
}

func fakeMidnight(hc *HopCache) {
	atomic.StoreInt32(&hc.hour, 24+1)
	time.Sleep(300 * time.Millisecond)
}

func TestAnnotate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	fa := &fakeAnnotator{}
	hc := New(ctx, fa, "./testdata")
	for i, test := range tests {
		if test.hops[0] == "clear-cache" {
			hc.Clear()
			continue
		}
		_, gotAllErrs := hc.Annotate(ctx, test.hops)
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
	}
	// Now cover the error paths that were not covered by the
	// above tests.
	cancel()
	_, gotAllErrs := hc.Annotate(ctx, tests[0].hops)
	if len(gotAllErrs) != 1 || gotAllErrs[0] != context.Canceled {
		t.Fatalf("got =%+v, want %v\n", gotAllErrs, context.Canceled)
	}
}

func TestWriteAnnotations(t *testing.T) {
	// Mock writeFile.
	saveWriteFile := writeFile
	writeFile = fakeWriteFile
	defer func() {
		writeFile = saveWriteFile
	}()

	ctx := context.TODO()
	fa := &fakeAnnotator{}
	hc := New(ctx, fa, "./testdata")
	for i, test := range tests {
		if test.hops[0] == "clear-cache" {
			hc.Clear()
			continue
		}
		annotations, _ := hc.Annotate(ctx, test.hops)
		if annotations != nil {
			hc.WriteAnnotations(annotations, time.Now())
		}
		// Verify the number of writeFile calls.
		if fakeWriteFileCalls != test.writeFileCalls {
			t.Fatalf("i=%d got %d writeFile calls, want %d", i, fakeWriteFileCalls, test.writeFileCalls)
		}
	}
	// Now cover the error paths that were not covered by the
	// above tests.
	hc = New(ctx, &fakeAnnotator{}, "/bad/path")
	annotations, _ := hc.Annotate(ctx, []string{"1.1.1.1", "2.2.2.2"})
	hc.WriteAnnotations(annotations, time.Now())
}
