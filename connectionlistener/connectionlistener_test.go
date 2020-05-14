package connectionlistener_test

import (
	"context"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/uuid"
	"github.com/m-lab/uuid-annotator/ipservice"

	"github.com/m-lab/traceroute-caller/connection"
	"github.com/m-lab/traceroute-caller/connectionlistener"
	"github.com/m-lab/traceroute-caller/ipcache"

	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/eventsocket"
)

type testData struct {
	data []byte
}

func (td testData) Serialize() string {
	return string(td.data)
}

func (td testData) AnnotateHops(client ipservice.Client) error {
	return nil
}

type fakeTracer struct {
	ips   []string
	mutex sync.Mutex
	wg    sync.WaitGroup
}

func (ft *fakeTracer) Trace(conn connection.Connection, t time.Time) (ipcache.TracerouteData, error) {
	ft.mutex.Lock() // Must have a lock to avoid race conditions around the append.
	defer ft.mutex.Unlock()
	log.Println("Tracing", conn)
	ft.ips = append(ft.ips, conn.RemoteIP)
	ft.wg.Done()
	return testData{data: []byte("Fake test Result")}, nil
}

func (ft *fakeTracer) TraceFromCachedTrace(conn connection.Connection, t time.Time, cachedTest ipcache.TracerouteData) error {
	log.Println("Create cached test for: ", conn)
	return nil
}

func (*fakeTracer) DontTrace(conn connection.Connection, err error) {}

func TestListener(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestEventSocketClient")
	rtx.Must(err, "Could not create tempdir")
	defer os.RemoveAll(dir)

	// Start up a eventsocket server
	srv := eventsocket.New(dir + "/tcpevents.sock")
	rtx.Must(srv.Listen(), "Could not listen")
	srvCtx, srvCancel := context.WithCancel(context.Background())
	defer srvCancel()
	go srv.Serve(srvCtx)

	// Create a new connectionlistener with a fake tracer.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ft := &fakeTracer{}
	cache := ipcache.New(ctx, ft, 100*time.Second, time.Second)

	ft.wg.Add(2)

	localIP := net.ParseIP("10.0.0.1")
	creator := connection.NewFakeCreator([]*net.IP{&localIP})
	cl := connectionlistener.New(creator, cache)
	cl.Open(ctx, time.Now(), "", nil) // Test that nil pointer to Open does not cause a crash.

	// Connect the connectionlistener to the server
	go eventsocket.MustRun(ctx, dir+"/tcpevents.sock", cl)

	// Give the client some time to connect
	time.Sleep(100 * time.Millisecond)

	// Send some events from the server
	// This spurious UUID should not cause a trace to occur.
	srv.FlowDeleted(time.Now(), uuid.FromCookie(10000))

	firstid := inetdiag.SockID{
		SPort:  2,
		DPort:  3,
		SrcIP:  "192.168.0.1",
		DstIP:  "10.0.0.1",
		Cookie: 1,
	}

	srv.FlowCreated(time.Now(), uuid.FromCookie(1), firstid)
	srv.FlowDeleted(time.Now(), uuid.FromCookie(1))
	secondid := firstid
	secondid.Cookie = 2
	srv.FlowCreated(time.Now(), uuid.FromCookie(2), secondid)
	srv.FlowDeleted(time.Now(), uuid.FromCookie(2))

	thirdid := inetdiag.SockID{
		SPort:  2,
		DPort:  3,
		DstIP:  "192.168.0.2",
		SrcIP:  "10.0.0.1",
		Cookie: 3,
	}
	srv.FlowCreated(time.Now(), uuid.FromCookie(3), thirdid)
	srv.FlowDeleted(time.Now(), uuid.FromCookie(3))

	badid := inetdiag.SockID{
		SPort:  2,
		DPort:  3,
		SrcIP:  "thisisnotanip",
		DstIP:  "neitheristhis",
		Cookie: 3,
	}
	srv.FlowCreated(time.Now(), uuid.FromCookie(4), badid)

	// Verify that the right calls were made to the fake tracer.
	ft.wg.Wait()
	sort.StringSlice(ft.ips).Sort()
	if diff := deep.Equal([]string{"192.168.0.1", "192.168.0.2"}, ft.ips); diff != nil {
		t.Error("Bad ips:", diff)
	}
}
