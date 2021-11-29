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
		resetCache     bool     // if true, reset the hop cache before test
		hops           []string // hops to annotate
		wantAllErrs    []error
		annotateCalls  int32
		writeFileCalls int32
	}{
		{false, []string{errorOnIP, errorOnIP}, []error{errForced}, 1, 0}, // we force the first call to Annotate() to fail
		{false, []string{"1.2.3.4", "5.6.7.8"}, nil, 2, 2},                // should annotate and archive both
		{false, []string{"1.2.3.4", "5.6.7.8"}, nil, 2, 2},                // should not annotate and archive either
		{true, []string{"1.2.3.4", "5.6.7.8"}, nil, 3, 4},                 // should annotate and archive both
		{false, []string{"5.6.7.8", "a:b:c:d::e"}, nil, 4, 5},             // should annotate and archive just one
		{false, []string{"1.2.3"}, []error{errInvalidIP}, 4, 5},           // should return error
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

func newHopCache(ctx context.Context, t *testing.T, path string) (*HopCache, *fakeAnnotator) {
	t.Helper()
	fa := &fakeAnnotator{}
	haCfg := Config{
		AnnotatorClient: fa,
		OutputPath:      path,
	}
	hopCache, err := New(ctx, haCfg)
	if err != nil {
		t.Fatalf("failed to create hop cache: %v", err)
	}
	return hopCache, fa
}

func TestNew(t *testing.T) {
	// Change ticker duration to 100ms to avoid waiting a long time for
	// the resetter goroutine to notice passage of midnight or cancelled
	// context.
	saveTickerIntvl := tickerDuration
	tickerDuration = int64(100 * time.Millisecond)
	defer func() {
		tickerDuration = saveTickerIntvl
	}()

	// Create a new hop cache and insert an entry in it.
	ctx, cancel := context.WithCancel(context.Background())
	hopCache, fa := newHopCache(ctx, t, "./testdata")
	hopCache.hopsLock.Lock()
	hopCache.hops["1.2.3.4-20210826"] = true
	hopCache.hopsLock.Unlock()

	// Fake we've reached midnight and verify that our current cache
	// has become the old cache and the new cache is empty.
	fakeMidnight(hopCache)
	hopCache.hopsLock.Lock()
	if len(hopCache.hops) != 0 {
		t.Fatal("failed to reset cache at midnight")
	}
	hopCache.hopsLock.Unlock()

	// Validate the following scenario:
	//   1. traceroute to a new IP starts right before midnight at 23:59:59
	//   2. traceroute output becomes available after midnight
	//   3. hop annotations for yesterday's traceroute happen today
	//   4. another traceroute to the same IP at starts at 1:00AM
	//   5. traceroute output becomes available at 1:10AM
	//   6. hop annotations should be done again for today's traceroute
	traceStartTime, _ := time.Parse(time.RFC3339, "2021-08-26T23:59:59Z")
	hopCache.Annotate(ctx, []string{"1.2.3.4"}, traceStartTime) // should annotate
	traceStartTime, _ = time.Parse(time.RFC3339, "2021-08-27T01:10:00Z")
	hopCache.Annotate(ctx, []string{"1.2.3.4"}, traceStartTime) // same IP, but should annotate again
	if fa.annotateCalls != 2 {
		t.Fatalf("got %d Annotate calls, want %d", fa.annotateCalls, 2)
	}

	// Cancel the context and verify the resetter goroutine has stopped.
	cancel()
	fakeMidnight(hopCache)
	if atomic.LoadInt32(&hopCache.hour) != 24 {
		t.Fatal("failed to stop the resetter goroutine")
	}
}

func fakeMidnight(hopCache *HopCache) {
	atomic.StoreInt32(&hopCache.hour, 24)
	time.Sleep(300 * time.Millisecond)
}

func TestAnnotate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	hopCache, fa := newHopCache(ctx, t, "./testdata")
	now := time.Now()
	for i, test := range tests {
		if test.resetCache {
			hopCache.Reset()
		}
		_, gotAllErrs := hopCache.Annotate(ctx, test.hops, now)
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
			t.Fatalf("i=%d hopCache.AnnotateArchive() = %+v, want: %+v", i, gotAllErrs, test.wantAllErrs)
		}
		// Verify the number of Annotate calls.
		if fa.annotateCalls != test.annotateCalls {
			t.Fatalf("i=%d got %d Annotate calls, want %d", i, fa.annotateCalls, test.annotateCalls)
		}
	}
	// Now cover the error paths that were not covered by the
	// above tests.
	cancel()
	_, gotAllErrs := hopCache.Annotate(ctx, tests[0].hops, now)
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
	hopCache, _ := newHopCache(ctx, t, "./testdata")
	now := time.Now()
	for i, test := range tests {
		if test.resetCache {
			hopCache.Reset()
		}
		annotations, _ := hopCache.Annotate(ctx, test.hops, now)
		if annotations != nil {
			hopCache.WriteAnnotations(annotations, now)
		}
		// Verify the number of writeFile calls.
		if fakeWriteFileCalls != test.writeFileCalls {
			t.Fatalf("i=%d got %d writeFile calls, want %d", i, fakeWriteFileCalls, test.writeFileCalls)
		}
	}
	// Now cover the error paths that were not covered by the
	// above tests.
	hopCache, _ = newHopCache(ctx, t, "/bad/path")
	annotations, _ := hopCache.Annotate(ctx, []string{"1.1.1.1", "2.2.2.2"}, now)
	hopCache.WriteAnnotations(annotations, now)
}
