package ipcache_test

import (
	"context"
	"log"
	"testing"
	"time"

	"github.com/m-lab/traceroute-caller/connection"
	"github.com/m-lab/traceroute-caller/ipcache"
)

func TestRecentIPCache(t *testing.T) {
	*ipcache.IPCacheTimeout = 100 * time.Millisecond
	*ipcache.IPCacheUpdatePeriod = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tmp := ipcache.New(ctx)
	tmp.Add("1.2.3.4")
	if !tmp.Has("1.2.3.4") {
		t.Error("cache not working correctly")
	}

	time.Sleep(300 * time.Millisecond)
	if tmp.Has("1.2.3.4") {
		t.Error("cache not expire correctly")
	}
	cancel()
	time.Sleep(200 * time.Millisecond)
}

type testTracer struct {
	calls   int
	answers []map[connection.Connection]struct{}
}

func (tf *testTracer) Trace(conn connection.Connection, t time.Time) string {
	log.Println("Create Trace Test")
	return "Fake Trace test " + conn.RemoteIP
}

func (tf *testTracer) CreateCacheTest(conn connection.Connection, t time.Time, cachedTest string) {
	log.Println("Create cached Test " + conn.RemoteIP)
	return
}

func TestTrace(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	testCache := ipcache.New(ctx)

	conn1 := connection.Connection{
		RemoteIP:   "1.1.1.2",
		RemotePort: 5034,
		LocalIP:    "1.1.1.3",
		LocalPort:  58790,
		Cookie:     "10f3d"}
	var tt testTracer

	testCache.Trace(conn1, &tt)
	time.Sleep(200 * time.Millisecond)
	if testCache.GetTestContent("1.1.1.2") != "Fake Trace test 1.1.1.2" {
		t.Error("cache not trace correctly ")
	}

	conn2 := connection.Connection{
		RemoteIP:   "1.1.1.5",
		RemotePort: 5034,
		LocalIP:    "1.1.1.7",
		LocalPort:  58790,
		Cookie:     "aaaa"}

	testCache.Trace(conn2, &tt)
	testCache.Trace(conn1, &tt)

	time.Sleep(200 * time.Millisecond)

	if testCache.GetCacheLength() != 2 {
		t.Error("cache not working correctly ")
	}
}
