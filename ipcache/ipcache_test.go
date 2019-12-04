package ipcache_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/m-lab/traceroute-caller/connection"
	"github.com/m-lab/traceroute-caller/ipcache"
)

type testTracer struct {
	calls   int
	cctest  int
	answers []map[connection.Connection]struct{}
}

func (tf *testTracer) Trace(conn connection.Connection, t time.Time) string {
	return "Fake trace test " + conn.RemoteIP
}

func (tf *testTracer) CreateCacheTest(conn connection.Connection, t time.Time, cachedTest string) {
	tf.cctest++
	return
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

	tmp := testCache.Trace(conn1)
	if tmp != "Fake trace test 1.1.1.2" {
		t.Error("cache not trace correctly ")
	}

	conn2 := connection.Connection{
		RemoteIP:   "1.1.1.5",
		RemotePort: 5034,
		LocalIP:    "1.1.1.3",
		LocalPort:  58790,
		Cookie:     "aaaa"}

	t2 := testCache.Trace(conn2)
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
		t.Error("cache not working correctly ")
	}
}

func TestRecentIPCache(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var tt testTracer
	tmp := ipcache.New(ctx, &tt, 100*time.Millisecond, 10*time.Millisecond)
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

	time.Sleep(300 * time.Millisecond)
	if tmp.GetCacheLength() != 0 {
		t.Error("Cache GC failed to collect garbage")
	}
	cancel()
	time.Sleep(200 * time.Millisecond)
}

type testPausingTracer struct {
	ctx          context.Context
	traceToBlock string
	mut          sync.Mutex
	successes    int
}

func (tpt *testPausingTracer) Trace(conn connection.Connection, t time.Time) string {
	time.Sleep(1 * time.Millisecond)
	if conn.RemoteIP == tpt.traceToBlock {
		<-tpt.ctx.Done()
	}
	tpt.mut.Lock()
	tpt.successes++
	tpt.mut.Unlock()
	return "Trace to " + conn.RemoteIP
}

func (tpt *testPausingTracer) CreateCacheTest(conn connection.Connection, t time.Time, cachedTest string) {
	tpt.mut.Lock()
	tpt.successes++
	tpt.mut.Unlock()
}

func TestCacheWithBlockedTests(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tpt := &testPausingTracer{
		ctx:          ctx,
		traceToBlock: "77",
	}
	c := ipcache.New(ctx, tpt, 100*time.Second, 10*time.Second)

	wg := sync.WaitGroup{}
	wg.Add(990) // 1 out of every 100 will be stalled.
	stalledWg := sync.WaitGroup{}
	stalledWg.Add(10) // The waitgroup for the stalled requests.

	for i := 0; i < 1000; i++ {
		go func(j int) {
			if s := c.Trace(connection.Connection{RemoteIP: fmt.Sprintf("%d", j)}); s != fmt.Sprintf("Trace to %d", j) {
				t.Errorf("Bad trace output: %q", s)
			}
			if j == 77 {
				stalledWg.Done()
			} else {
				wg.Done()
			}
		}(i % 100)
	}
	wg.Wait()
	if tpt.successes != 990 {
		t.Errorf("Expected 990 successes, not %d", tpt.successes)
	}
	cancel() // Unblock the stalled tests.
	stalledWg.Wait()
	if tpt.successes != 1000 {
		t.Errorf("Expected 1000 successes, not %d", tpt.successes)
	}
}
