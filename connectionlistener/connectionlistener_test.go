package connectionlistener_test

import (
	"context"
	"io/ioutil"
	"log"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/uuid"

	"github.com/m-lab/traceroute-caller/connection"
	"github.com/m-lab/traceroute-caller/connectionlistener"
	"github.com/m-lab/traceroute-caller/ipcache"

	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/eventsocket"
)

type fakeTracer struct {
	ips []string
	wg  sync.WaitGroup
}

func (ft *fakeTracer) Trace(conn connection.Connection, t time.Time) {
	log.Println("Tracing", conn)
	ft.ips = append(ft.ips, conn.RemoteIP)
	ft.wg.Done()
}

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
	cache := ipcache.New(ctx)
	ft := &fakeTracer{}
	ft.wg.Add(2)

	cl := connectionlistener.New(ft, cache)

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
		SrcIP:  "192.168.0.2",
		DstIP:  "10.0.0.1",
		Cookie: 3,
	}
	srv.FlowCreated(time.Now(), uuid.FromCookie(3), thirdid)
	srv.FlowDeleted(time.Now(), uuid.FromCookie(3))

	// Verify that the right calls were made to the fake tracer.
	ft.wg.Wait()
	sort.StringSlice(ft.ips).Sort()
	if diff := deep.Equal([]string{"192.168.0.1", "192.168.0.2"}, ft.ips); diff != nil {
		t.Error("Bad ips:", diff)
	}
}
