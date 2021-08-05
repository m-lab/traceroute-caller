package connectionlistener_test

import (
	"context"
	"errors"
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
	"github.com/m-lab/uuid-annotator/annotator"
)

var (
	// We assign these to conn.Cookie to test different kinds of
	// errors in our fake Trace().
	traceFailed      = int64(0x1001)
	traceNoTracelb   = int64(0x1002)
	traceInvalidType = int64(0x1003)
	traceNoNodes     = int64(0x1004)

	sockIDGolden = inetdiag.SockID{
		SPort:  2,
		DPort:  3,
		SrcIP:  "",
		DstIP:  "10.0.0.1",
		Cookie: 0,
	}
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

type fakeAnnotator struct {
}

func (fa *fakeAnnotator) Annotate(ctx context.Context, ips []string) (map[string]*annotator.ClientAnnotations, error) {
	annotations := make(map[string]*annotator.ClientAnnotations, len(ips))
	for _, ip := range ips {
		annotations[ip] = &annotator.ClientAnnotations{}
	}
	return annotations, errors.New("forced annotation error")
}

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

	// Create a new IP cache.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ft := &fakeTracer{}
	ipCache := ipcache.New(ctx, ft, 100*time.Second, time.Second)

	// Create a new hop cache.
	localIP := net.ParseIP("10.0.0.1")
	localIPs := connection.NewFakeLocalIPs([]*net.IP{&localIP})
	hopAnnotator := hopannotation.New(&fakeAnnotator{}, "./testdata")

	// Create a new connectionlistener with our fake tracer and hop
	// cache, connect the connectionlistener to the server and give
	// the client some time to connect.
	cl := connectionlistener.New(localIPs, ipCache, hopAnnotator)
	go eventsocket.MustRun(ctx, dir+"/tcpevents.sock", cl)
	time.Sleep(100 * time.Millisecond)

	runTests(t, srv, ft, cl)
}

func runTests(t *testing.T, srv eventsocket.Server, ft *fakeTracer, cl eventsocket.Handler) {
	// This event should not cause a trace because there was no
	// FlowCreated call for this UUID.
	srv.FlowDeleted(time.Now(), uuid.FromCookie(0))
	// Make sure nil sockID does not crash Open().
	cl.Open(context.Background(), time.Now(), "", nil)

	tests := []struct {
		srcIP     string
		cookie    uint64
		goroutine bool
	}{
		{"192.168.0.1", uint64(traceFailed), true},      // should cause a trace but we force our fake Trace() to fail
		{"192.168.0.2", uint64(traceNoTracelb), true},   // failed to extract tracelb from trace output (error: %v)
		{"192.168.0.3", uint64(traceInvalidType), true}, // tracelb output has invalid type: %q
		{"192.168.0.4", uint64(traceNoNodes), true},     // tracelb output has no nodes
		{"192.168.0.5", 0, true},                        // good trace
		{"invalidip", 0, false},                         // cannot create...
	}
	for i, test := range tests {
		if test.goroutine {
			ft.wg.Add(1)
		}
		sockID1 := sockIDGolden
		sockID1.SrcIP = test.srcIP
		sockID1.Cookie = int64(test.cookie)
		srv.FlowCreated(time.Now(), uuid.FromCookie(uint64(i)+1), sockID1)
		srv.FlowDeleted(time.Now(), uuid.FromCookie(uint64(i)+1))
		if test.goroutine {
			ft.wantIPs = append(ft.wantIPs, sockID1.SrcIP)
			ft.wg.Wait()
		}
	}
	// Give traceAnnotateArchive() a chance to finish.
	time.Sleep(1 * time.Second)

	// Check the results.
	sort.StringSlice(ft.gotIPs).Sort()
	if diff := deep.Equal(ft.gotIPs, ft.wantIPs); diff != nil {
		t.Errorf("IPs: %+v, want: %v", ft.gotIPs, ft.wantIPs)
	}
}
