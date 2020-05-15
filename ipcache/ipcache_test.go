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

	"github.com/m-lab/go/rtx"
	"github.com/m-lab/traceroute-caller/connection"
	"github.com/m-lab/traceroute-caller/ipcache"
	"github.com/m-lab/uuid-annotator/ipservice"
	pipe "gopkg.in/m-lab/pipe.v3"
)

type testTracer struct {
	calls   int
	cctest  int
	answers []map[connection.Connection]struct{}
}

type testData struct {
	data []byte
}

func (td testData) GetData() []byte {
	return td.data
}

func (td testData) AnnotateHops(client ipservice.Client) error {
	return nil
}

func (td testData) CachedTraceroute(newUUID string) ipcache.TracerouteData {
	return td
}

func (tf *testTracer) Trace(conn connection.Connection, t time.Time) (ipcache.TracerouteData, error) {
	tf.calls++
	return testData{data: []byte("Fake trace test " + conn.RemoteIP)}, nil
}

func (tf *testTracer) TraceFromCachedTrace(conn connection.Connection, t time.Time, cachedTest ipcache.TracerouteData) error {
	tf.cctest++
	return nil
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
	if string(tmp.GetData()) != "Fake trace test 1.1.1.2" {
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
	if string(t2.GetData()) != "Fake trace test 1.1.1.5" {
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

func TestUpdateTracer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var tt, tt2 testTracer
	testCache := ipcache.New(ctx, &tt, 100*time.Second, time.Second)
	conn1 := connection.Connection{
		RemoteIP:   "1.1.1.2",
		RemotePort: 5034,
		LocalIP:    "1.1.1.3",
		LocalPort:  58790,
		Cookie:     "10f3d"}
	_, err := testCache.Trace(conn1)
	rtx.Must(err, "Could not trace using tt")

	testCache.UpdateTracer(&tt2)
	conn2 := connection.Connection{
		RemoteIP:   "1.1.1.5",
		RemotePort: 5034,
		LocalIP:    "1.1.1.3",
		LocalPort:  58790,
		Cookie:     "aaaa"}
	_, err = testCache.Trace(conn2)
	rtx.Must(err, "Could not trace using tt2")

	if tt.calls != 1 || tt2.calls != 1 {
		t.Error("Each tracer should have been called once, not", tt.calls, tt2.calls)
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

func (pt *pausingTracer) Trace(conn connection.Connection, t time.Time) (ipcache.TracerouteData, error) {
	randomDelay()
	if conn.RemoteIP == pt.traceToBlock || conn.RemoteIP == pt.traceToBlockAndError {
		<-pt.ctx.Done()
	}
	atomic.AddInt64(&pt.successes, 1)
	if conn.RemoteIP == pt.traceToError || conn.RemoteIP == pt.traceToBlockAndError {
		return nil, errors.New(pipe.ErrTimeout.Error())
	}
	return testData{data: []byte("Trace to " + conn.RemoteIP)}, nil
}

func (pt *pausingTracer) TraceFromCachedTrace(conn connection.Connection, t time.Time, cachedTest ipcache.TracerouteData) error {
	randomDelay()
	atomic.AddInt64(&pt.successes, 1)
	return nil
}

func (pt *pausingTracer) DontTrace(conn connection.Connection, err error) {
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
	log.Printf("%+v\n", pt)
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
			if j == justError || j == blockThenError {
				if err == nil {
					t.Error("Should have had an error")
				}
			} else {
				if err != nil {
					t.Errorf("Trace %d not done correctly.", j)
				}
				if string(s.GetData()) != expected {
					t.Errorf("Bad trace output: %q, should be %s", string(s.GetData()), expected)
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
	if atomic.LoadInt64(&pt.successes) != 980 {
		t.Errorf("Expected 980 successes, not %d", atomic.LoadInt64(&pt.successes))
	}
	cancel() // Unblock the stalled tests.
	stalledWg.Wait()
	if atomic.LoadInt64(&pt.successes) != 1000 {
		t.Errorf("Expected 1000 successes, not %d", pt.successes)
	}
}
