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

	"github.com/m-lab/traceroute-caller/connection"
	"github.com/m-lab/traceroute-caller/connectionlistener"
	"github.com/m-lab/traceroute-caller/hopannotation"
	"github.com/m-lab/traceroute-caller/ipcache"

	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/eventsocket"
	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/uuid"
	"github.com/m-lab/uuid-annotator/ipservice"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

type fakeTracer struct {
	ips   []string
	mutex sync.Mutex
	wg    sync.WaitGroup
}

func (ft *fakeTracer) Trace(conn connection.Connection, t time.Time) ([]byte, error) {
	ft.mutex.Lock() // Must have a lock to avoid race conditions around the append.
	defer ft.mutex.Unlock()
	log.Println("Tracing", conn)
	ft.ips = append(ft.ips, conn.RemoteIP)
	ft.wg.Done()
	return ioutil.ReadFile("testdata/trace-output.jsonl")
}

func (ft *fakeTracer) TraceFromCachedTrace(conn connection.Connection, t time.Time, cachedTest []byte) error {
	log.Println("Create cached test for: ", conn)
	return nil
}

func (*fakeTracer) DontTrace(conn connection.Connection, err error) {}

func TestListener(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestEventSocketClient")
	rtx.Must(err, "Could not create tempdir")
	defer os.RemoveAll(dir)

	// Start up an eventsocket server.
	srv := eventsocket.New(dir + "/tcpevents.sock")
	rtx.Must(srv.Listen(), "Could not listen")
	srvCtx, srvCancel := context.WithCancel(context.Background())
	defer srvCancel()
	go func() {
		_ = srv.Serve(srvCtx)
	}()

	// Create a new connectionlistener with a fake tracer.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ft := &fakeTracer{}
	ipCache := ipcache.New(ctx, ft, 100*time.Second, time.Second)

	ft.wg.Add(2)

	localIP := net.ParseIP("10.0.0.1")
	localIPs := connection.NewFakeLocalIPs([]*net.IP{&localIP})
	hopAnnotator := hopannotation.New(ipservice.NewClient(*ipservice.SocketFilename), "/some/path")
	cl := connectionlistener.New(localIPs, ipCache, hopAnnotator)
	// Test that nil pointer to Open does not cause a crash.
	// The actual Open and Close methods will be called indirectly
	// through srv.FlowCreateed and srv.FlowDeleted calls below.
	cl.Open(ctx, time.Now(), "", nil)

	// Connect the connectionlistener to the server and
	// give the client some time to connect.
	go eventsocket.MustRun(ctx, dir+"/tcpevents.sock", cl)
	time.Sleep(100 * time.Millisecond)

	// Now send some events from the server.

	// This event should not cause a trace to occur because
	// there was no FlowCreated call for this UUID.
	srv.FlowDeleted(time.Now(), uuid.FromCookie(1))

	// This event should cause a trace.
	sockID1 := inetdiag.SockID{
		SPort:  2,
		DPort:  3,
		SrcIP:  "192.168.0.1",
		DstIP:  "10.0.0.1",
		Cookie: 1,
	}
	srv.FlowCreated(time.Now(), uuid.FromCookie(1), sockID1)
	srv.FlowDeleted(time.Now(), uuid.FromCookie(1))

	// This event should cause a trace to 192.168.0.1.
	sockID2 := sockID1
	sockID2.Cookie = 2
	srv.FlowCreated(time.Now(), uuid.FromCookie(2), sockID2)
	srv.FlowDeleted(time.Now(), uuid.FromCookie(2))

	// This event should cause a trace to 192.168.0.2.
	sockID3 := inetdiag.SockID{
		SPort:  2,
		DPort:  3,
		DstIP:  "192.168.0.2",
		SrcIP:  "10.0.0.1",
		Cookie: 3,
	}
	srv.FlowCreated(time.Now(), uuid.FromCookie(3), sockID3)
	srv.FlowDeleted(time.Now(), uuid.FromCookie(3))

	// This event should cause an error.
	badid := inetdiag.SockID{
		SPort:  2,
		DPort:  3,
		SrcIP:  "thisisnotanip",
		DstIP:  "neitheristhis",
		Cookie: 3,
	}
	srv.FlowCreated(time.Now(), uuid.FromCookie(4), badid)

	// Allow the goroutines that were started by Close() to finish.
	time.Sleep(1 * time.Second)

	// Verify that the right calls were made to the fake tracer.
	ft.wg.Wait()
	sort.StringSlice(ft.ips).Sort()
	if diff := deep.Equal([]string{"192.168.0.1", "192.168.0.2"}, ft.ips); diff != nil {
		t.Error("Bad ips:", diff)
	}
}
