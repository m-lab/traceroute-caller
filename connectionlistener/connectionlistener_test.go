package connectionlistener_test

import (
	"context"
	"fmt"
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

var (
	// We assign these to conn.Cookie to test different kinds of
	// errors in our fake Trace().
	traceFailed      = int64(0x1001)
	traceNoTracelb   = int64(0x1002)
	traceInvalidType = int64(0x1003)
	traceNoNodes     = int64(0x1004)
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

type fakeTracer struct {
	gotIPs  []string
	wantIPs []string
	mutex   sync.Mutex
	wg      sync.WaitGroup
}

func (ft *fakeTracer) Trace(conn connection.Connection, t time.Time) ([]byte, error) {
	var traceFile string
	switch conn.Cookie {
	case fmt.Sprintf("%x", traceFailed):
		traceFile = "testdata/trace-non-existent.jsonl"
	case fmt.Sprintf("%x", traceNoTracelb):
		traceFile = "testdata/trace-no-tracelb.jsonl"
	case fmt.Sprintf("%x", traceInvalidType):
		traceFile = "testdata/trace-tracelb-invalid-type.jsonl"
	case fmt.Sprintf("%x", traceNoNodes):
		traceFile = "testdata/trace-tracelb-no-nodes.jsonl"
	default:
		traceFile = "testdata/trace-good.jsonl"
	}
	ft.mutex.Lock() // Must have a lock to avoid race conditions around the append.
	defer ft.mutex.Unlock()
	log.Println("Tracing", conn)
	ft.gotIPs = append(ft.gotIPs, conn.RemoteIP)
	ft.wg.Done()
	return ioutil.ReadFile(traceFile)
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

	// Connect the connectionlistener to the server and
	// give the client some time to connect.
	localIP := net.ParseIP("10.0.0.1")
	localIPs := connection.NewFakeLocalIPs([]*net.IP{&localIP})
	hopAnnotator := hopannotation.New(ipservice.NewClient(*ipservice.SocketFilename), "/some/path")
	cl := connectionlistener.New(localIPs, ipCache, hopAnnotator)
	go eventsocket.MustRun(ctx, dir+"/tcpevents.sock", cl)
	time.Sleep(100 * time.Millisecond)

	runTests(t, srv, ft, hopAnnotator)
	sort.StringSlice(ft.gotIPs).Sort()
	if diff := deep.Equal(ft.gotIPs, ft.wantIPs); diff != nil {
		t.Errorf("got ips %+v, want %v", ft.gotIPs, ft.wantIPs)
	}
}

// XXX The tests in this function should be placed in a table.
func runTests(t *testing.T, srv eventsocket.Server, ft *fakeTracer, hopAnnotator *hopannotation.HopCache) {
	sockID0 := inetdiag.SockID{
		SPort:  2,
		DPort:  3,
		SrcIP:  "192.168.0.1",
		DstIP:  "10.0.0.1",
		Cookie: 0,
	}

	// This event should not cause a trace because there was no
	// FlowCreated call for this UUID.
	srv.FlowDeleted(time.Now(), uuid.FromCookie(0))

	// This should cause a trace but we force our fake Trace() to fail.
	ft.wg.Add(1)
	sockID1 := sockID0
	sockID1.Cookie = traceFailed
	srv.FlowCreated(time.Now(), uuid.FromCookie(1), sockID1)
	srv.FlowDeleted(time.Now(), uuid.FromCookie(1))
	ft.wantIPs = append(ft.wantIPs, sockID1.SrcIP)
	ft.wg.Wait()

	// This event should cause a trace but trace doesn't have tracelb.
	// failed to extract tracelb from trace output (error: %v)
	ft.wg.Add(1)
	sockID2 := sockID0
	sockID2.SrcIP = "192.168.0.2"
	sockID2.Cookie = traceNoTracelb
	srv.FlowCreated(time.Now(), uuid.FromCookie(2), sockID2)
	srv.FlowDeleted(time.Now(), uuid.FromCookie(2))
	ft.wantIPs = append(ft.wantIPs, sockID2.SrcIP)
	ft.wg.Wait()

	// This event should cause a trace but trace type is invalid.
	// tracelb output has invalid type: %q"
	ft.wg.Add(1)
	sockID3 := sockID0
	sockID3.SrcIP = "192.168.0.3"
	sockID3.Cookie = traceInvalidType
	srv.FlowCreated(time.Now(), uuid.FromCookie(3), sockID3)
	srv.FlowDeleted(time.Now(), uuid.FromCookie(3))
	ft.wantIPs = append(ft.wantIPs, sockID3.SrcIP)
	ft.wg.Wait()

	// This event should cause a trace but trace has no nodes.
	// tracelb output has no nodes
	ft.wg.Add(1)
	sockID4 := sockID0
	sockID4.SrcIP = "192.168.0.4"
	sockID4.Cookie = traceNoNodes
	srv.FlowCreated(time.Now(), uuid.FromCookie(4), sockID4)
	srv.FlowDeleted(time.Now(), uuid.FromCookie(4))
	ft.wantIPs = append(ft.wantIPs, sockID4.SrcIP)
	ft.wg.Wait()

	// This event should cause a trace to 192.168.0.5.
	ft.wg.Add(1)
	sockID5 := sockID0
	sockID5.SrcIP = "192.168.0.5"
	srv.FlowCreated(time.Now(), uuid.FromCookie(5), sockID5)
	srv.FlowDeleted(time.Now(), uuid.FromCookie(5))
	ft.wantIPs = append(ft.wantIPs, sockID5.SrcIP)
	ft.wg.Wait()

	// This event should cause an error due to bad IPs.
	sockID7 := sockID0
	sockID7.SrcIP = "thisisnotanip"
	sockID7.DstIP = "neitheristhis"
	srv.FlowCreated(time.Now(), uuid.FromCookie(7), sockID7)
	srv.FlowDeleted(time.Now(), uuid.FromCookie(7))
}
