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

	"github.com/m-lab/traceroute-caller/connection"
	"github.com/m-lab/traceroute-caller/ipcache"
	pipe "gopkg.in/m-lab/pipe.v3"
)

type testTracer struct {
	calls   int
	cctest  int
	answers []map[connection.Connection]struct{}
}

func (tf *testTracer) Trace(conn connection.Connection, t time.Time) (string, error) {
	return "Fake trace test " + conn.RemoteIP, nil
}

func (tf *testTracer) CreateCacheTest(conn connection.Connection, t time.Time, cachedTest string) {
	tf.cctest++
}

func (tf *testTracer) DontTrace(conn connection.Connection, err error) {
	log.Fatal("This function should not be called")
}

func TestTrace(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var tt testTracer
	testCache := ipcache.New(ctx, &tt, 100*time.Second, time.Second)

	conn1 := connection.Connection{
		RemoteIP:   "1.1.1.2",
		RemotePort: 5034,
		LocalIP:    "1.1.1.3",
		LocalPort:  58790,
		Cookie:     "10f3d"}

	tmp, err := testCache.Trace(conn1)
	if err != nil {
		t.Error("trace not working correctly.")
	}
	if tmp != "Fake trace test 1.1.1.2" {
		t.Error("cache not trace correctly ")
	}

	conn2 := connection.Connection{
		RemoteIP:   "1.1.1.5",
		RemotePort: 5034,
		LocalIP:    "1.1.1.3",
		LocalPort:  58790,
		Cookie:     "aaaa"}

	t2, err := testCache.Trace(conn2)
	if err != nil {
		t.Error("trace not working correctly.")
	}
	if t2 != "Fake trace test 1.1.1.5" {
		t.Error("cache did not trace")
	}
	if tt.cctest != 0 {
		t.Errorf("Should have had zero calls to CreateCachedTest, not %d", tt.cctest)
	}
	testCache.Trace(conn1) // This should be cached
	if tt.cctest != 1 {
		t.Errorf("Should have had one call to CreateCachedTest, not %d", tt.cctest)
	}
	if testCache.GetCacheLength() != 2 {
		t.Error("cache not working correctly.")
	}
}

func TestRecentIPCache(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var tt testTracer
	tmp := ipcache.New(ctx, &tt, 10*time.Millisecond, 1*time.Millisecond)
	tmp.Trace(connection.Connection{
		RemoteIP:   "1.2.3.4",
		RemotePort: 5,
		LocalIP:    "6.7.8.9",
		LocalPort:  10,
		Cookie:     "11",
	})
	if tmp.GetCacheLength() != 1 {
		t.Error("Did not put an entry into the cache")
	}

	time.Sleep(30 * time.Millisecond)
	if tmp.GetCacheLength() != 0 {
		t.Error("Cache GC failed to collect garbage")
	}
	cancel()
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
	mut                  sync.Mutex
	successes            int64
}

func (pt *pausingTracer) Trace(conn connection.Connection, t time.Time) (string, error) {
	randomDelay()
	if conn.RemoteIP == pt.traceToBlock || conn.RemoteIP == pt.traceToError {
		<-pt.ctx.Done()
	}
	atomic.AddInt64(&pt.successes, 1)
	if conn.RemoteIP == pt.traceToError || conn.RemoteIP == pt.traceToBlockAndError {
		return "", errors.New(pipe.ErrTimeout.Error())
	}
	return "Trace to " + conn.RemoteIP, nil
}

func (pt *pausingTracer) CreateCacheTest(conn connection.Connection, t time.Time, cachedTest string) {
	randomDelay()
	atomic.AddInt64(&pt.successes, 1)
}

func (pt *pausingTracer) DontTrace(conn connection.Connection, err error) {
	randomDelay()
	atomic.AddInt64(&pt.successes, 1)
}

func TestCacheWithBlockedTests(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pt := &pausingTracer{
		ctx:                  ctx,
		traceToBlock:         "77",
		traceToBlockAndError: "33",
		traceToError:         "90",
	}
	c := ipcache.New(ctx, pt, 10*time.Microsecond, 1*time.Microsecond)

	wg := sync.WaitGroup{}
	wg.Add(980) // 2 out of every 100 will be stalled - one with errors and one without.
	stalledWg := sync.WaitGroup{}
	stalledWg.Add(20) // The waitgroup for the stalled requests.

	for i := 0; i < 1000; i++ {
		go func(j int) {
			randomDelay()
			s, err := c.Trace(connection.Connection{RemoteIP: fmt.Sprintf("%d", j)})
			expected := fmt.Sprintf("Trace to %d", j)
			if j == 90 || j == 33 {
				if err == nil {
					t.Error("Should have had an error")
				}
			} else {
				if err != nil {
					t.Errorf("Trace %d not done correctly.", j)
				}
				if s != expected {
					t.Errorf("Bad trace output: %q, should be %s", s, expected)
				}
			}
			if j == 77 || j == 90 {
				stalledWg.Done()
			} else {
				wg.Done()
			}
		}(i % 100)
	}
	wg.Wait()
	if atomic.LoadInt64(&pt.successes) != 980 {
		t.Errorf("Expected 980 successes, not %d", atomic.LoadInt64(&pt.successes))
	}
	cancel() // Unblock the stalled tests.
	stalledWg.Wait()
	if atomic.LoadInt64(&pt.successes) != 1000 {
		t.Errorf("Expected 1000 successes, not %d", pt.successes)
	}
}
