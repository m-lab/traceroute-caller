package ipcache_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/m-lab/traceroute-caller/ipcache"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

type fakeTracer struct {
	nTrace       int
	nCachedTrace int
}

func (ft *fakeTracer) Trace(remoteIP, cookie, uuid string, t time.Time) ([]byte, error) {
	ft.nTrace++
	return []byte("fake traceroute data to " + remoteIP), nil
}

func (ft *fakeTracer) CachedTrace(cookie, uuid string, t time.Time, cachedTest []byte) error {
	ft.nCachedTrace++
	return nil
}

func (ft *fakeTracer) DontTrace() {
	log.Fatal("should not have called DontTrace()")
}

func TestNew(t *testing.T) {
	// nolint:staticcheck
	if _, err := ipcache.New(nil, nil, ipcache.Config{}); err == nil {
		t.Error("FetchTrace() = nil, want error")
	}
	if _, err := ipcache.New(context.TODO(), &fakeTracer{}, ipcache.Config{}); err == nil {
		t.Error("FetchTrace() = nil, want error")
	}
}

func TestFetchTrace(t *testing.T) {
	tests := []struct {
		remoteIP             string
		cookie               string
		wantErr              bool
		wantData             string
		wantTraceCalls       int
		wantCachedTraceCalls int
		wantEntries          int
	}{
		{"1.1.1.1", "", true, "", 0, 0, 0},
		{"1.1.1.1", "10f3d", false, "fake traceroute data to 1.1.1.1", 1, 0, 1},
		{"1.1.1.2", "abcde", false, "fake traceroute data to 1.1.1.2", 2, 0, 2},
		{"1.1.1.2", "bcdef", false, "fake traceroute data to 1.1.1.2", 2, 1, 2}, // should be cached
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tracer := &fakeTracer{}
	entryTTL := 2 * time.Second
	ipCfg := ipcache.Config{
		EntryTimeout: entryTTL,
		ScanPeriod:   time.Second,
	}
	ipCache, err := ipcache.New(ctx, tracer, ipCfg)
	if err != nil {
		t.Fatalf("failed to create an IP cache: %v", err)
	}

	for _, test := range tests {
		data, err := ipCache.FetchTrace(test.remoteIP, test.cookie)
		if test.wantErr {
			if err == nil {
				t.Errorf("FetchTrace(%s) = nil, want error", test.remoteIP)
			}
		} else {
			if err != nil {
				t.Errorf("FetchTrace(%s) = %v, want nil", test.remoteIP, err)
			}
		}
		if gotData := string(data); gotData != test.wantData {
			t.Errorf("FetchTrace(%q) = %q, want %q", test.remoteIP, gotData, test.wantData)
		}
		if gotCalls := tracer.nTrace; gotCalls != test.wantTraceCalls {
			t.Errorf("got %d calls to Trace(), want %d", gotCalls, test.wantTraceCalls)
		}
		if gotCalls := tracer.nCachedTrace; gotCalls != test.wantCachedTraceCalls {
			t.Errorf("got %d calls to CachedTrace(), want %d", gotCalls, test.wantCachedTraceCalls)
		}
		if gotEntries := ipCache.NumEntries(); gotEntries != test.wantEntries {
			t.Errorf("got %d entries in IP cache, want %d", gotEntries, test.wantEntries)
		}
	}
	// Verify entries in the IP cache are purged.
	time.Sleep(entryTTL + time.Second)
	if gotEntries := ipCache.NumEntries(); gotEntries != 0 {
		t.Errorf("got %d entries in IP cache, want 0", gotEntries)
	}
}

func randomDelay() {
	// Uniform 0 to 20 usec.
	time.Sleep(time.Duration(rand.Intn(20000)) * time.Nanosecond)
}

type pausingTracer struct {
	ctx                  context.Context
	traceToBlock         string
	traceToBlockAndError string
	traceToError         string
	successes            int64
}

func (pt *pausingTracer) Trace(remoteIP, cookie, uuid string, t time.Time) ([]byte, error) {
	randomDelay()
	if remoteIP == pt.traceToBlock || remoteIP == pt.traceToBlockAndError {
		<-pt.ctx.Done()
	}
	atomic.AddInt64(&pt.successes, 1)
	if remoteIP == pt.traceToError || remoteIP == pt.traceToBlockAndError {
		return nil, errors.New("timeout")
	}
	return []byte("fake traceroute data to " + remoteIP), nil
}

func (pt *pausingTracer) CachedTrace(cookie, uuid string, t time.Time, cachedTest []byte) error {
	randomDelay()
	atomic.AddInt64(&pt.successes, 1)
	return nil
}

func (pt *pausingTracer) DontTrace() {
	randomDelay()
	atomic.AddInt64(&pt.successes, 1)
}

func TestCacheWithBlockedTests(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	block := 77
	blockThenError := 33
	justError := 90
	pt := &pausingTracer{
		ctx:                  ctx,
		traceToBlock:         fmt.Sprintf("%d", block),
		traceToBlockAndError: fmt.Sprintf("%d", blockThenError),
		traceToError:         fmt.Sprintf("%d", justError),
	}
	ipCfg := ipcache.Config{
		EntryTimeout: 10 * time.Microsecond,
		ScanPeriod:   1 * time.Microsecond,
	}
	c, err := ipcache.New(ctx, pt, ipCfg)
	if err != nil {
		t.Fatalf("failed to create an IP cache: %v", err)
	}
	wg := sync.WaitGroup{}
	wantSuccesses := 980 // 2 out of every 100 will be stalled - one with errors and one without.
	wg.Add(wantSuccesses)
	stalledWg := sync.WaitGroup{}
	stalledWg.Add(20) // The waitgroup for the stalled requests.

	for i := 0; i < 1000; i++ {
		go func(j int) {
			randomDelay()
			data, err := c.FetchTrace(fmt.Sprintf("%d", j), "abcde")
			wantData := fmt.Sprintf("fake traceroute data to %d", j)
			if j == justError || j == blockThenError {
				if err == nil {
					t.Errorf("FetchTrace(%d) = nil, want error", j)
				}
			} else {
				if err != nil {
					t.Errorf("FetchTrace(%d) = %v, want nil", j, err)
				}
				if gotData := string(data); gotData != wantData {
					t.Errorf("FetchTrace(%d) = %q, want %q", j, gotData, wantData)
				}
			}
			if j == block || j == blockThenError {
				stalledWg.Done()
			} else {
				wg.Done()
			}
		}(i % 100)
	}
	wg.Wait()
	if gotSuccesses := atomic.LoadInt64(&pt.successes); gotSuccesses != int64(wantSuccesses) {
		t.Errorf("got %d successes, want %d", gotSuccesses, int64(wantSuccesses))
	}
	cancel() // Unblock the stalled tests.
	stalledWg.Wait()
	wantSuccesses = 1000
	if gotSuccesses := atomic.LoadInt64(&pt.successes); gotSuccesses != int64(wantSuccesses) {
		t.Errorf("got %d successes, want %d", gotSuccesses, int64(wantSuccesses))
	}
}
