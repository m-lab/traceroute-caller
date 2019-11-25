// The package is not connectionpoller_test to allow us to test unexported funcs
package connectionpoller

import (
	"context"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/m-lab/traceroute-caller/ipcache"

	"github.com/m-lab/go/rtx"
	"github.com/m-lab/traceroute-caller/connection"
)

func TestParseIPAndPort(t *testing.T) {
	ip, port, err := parseIPAndPort("[2620:0:1003:416:a0ad:fd1a:62f:c862]:53890")
	if err != nil || ip != "2620:0:1003:416:a0ad:fd1a:62f:c862" || port != 53890 {
		t.Error("IPv6 and port not parsed correctly")
	}

	ip, port, err = parseIPAndPort("100.101.236.46:56374")
	if err != nil || ip != "100.101.236.46" || port != 56374 {
		t.Error("IPv4 and port not parsed correctly")
	}

	_, _, err = parseIPAndPort("notanip:123")
	if err == nil {
		log.Println("Should have had an error on a bad ip")
	}

	_, _, err = parseIPAndPort("1.2.3.4:notaport")
	if err == nil {
		log.Println("Should have had an error on a bad port")
	}

	_, _, err = parseIPAndPort("not an address at all")
	if err == nil {
		log.Println("Should have had an error on bad input")
	}

	_, _, err = parseIPAndPort("127.0.0.1:1")
	if err == nil {
		log.Println("Should have had an error on an ignored IP")
	}
}

func TestParseCookie(t *testing.T) {
	cookie, err := parseCookie("sk:1d10")
	if err != nil || cookie != "1d10" {
		t.Error("Cookie not parsed correctly")
	}
}

func TestSSLogsFatalOnError(t *testing.T) {
	// Cleanup
	defer func(s string) {
		*ssBinary = s
		logFatal = log.Fatal
	}(*ssBinary)

	*ssBinary = "/bin/false"
	logFatal = func(args ...interface{}) {
		panic("An expected failure for testing")
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Error("We were supposed to panic and did not")
		}
	}()

	f := &ssFinder{}
	f.GetConnections()
}

func TestParseSSLine(t *testing.T) {
	conn, err := parseSSLine("tcp   ESTAB      0      0         [2620:0:1003:416:a0ad:fd1a:62f:c862]:58790                       [2607:f8b0:400d:c0d::81]:5034                  timer:(keepalive,5.980ms,0) ino:6355539 sk:10f3d <->")
	if err != nil {
		t.Error("ss output not parsed correctly")
	}
	expected := &connection.Connection{
		RemoteIP:   "2607:f8b0:400d:c0d::81",
		RemotePort: 5034,
		LocalIP:    "2620:0:1003:416:a0ad:fd1a:62f:c862",
		LocalPort:  58790,
		Cookie:     "10f3d"}
	if !reflect.DeepEqual(conn, expected) {
		t.Errorf("Expected %v, got %v for parse ss line", expected, conn)
	}
}

func TestGetConnectionsWithFakeSS(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "TestConnectionWithFakeSS")
	rtx.Must(err, "Could not create tempdir")
	defer os.RemoveAll(tmpdir)

	// Print out five connections, one of which has no cookie, another of which is not a tcp connection, two more with bad local or remote IPs, and one good one.
	fakeSS := `#!/bin/bash
	echo 'tcp   ESTAB      0      0         [2620:0:1003:416:a0ad:fd1a:62f:c862]:58791                       [2607:f8b0:400d:c0d::81]:5034                  timer:(keepalive,5.980ms,0) ino:6355540 <->'
	echo 'nottcp   ESTAB      0      0         [2620:0:1003:416:a0ad:fd1a:62f:c862]:58792                       [2607:f8b0:400d:c0d::81]:5034                  timer:(keepalive,5.980ms,0) ino:6355539 sk:10f3d <->'
	echo 'tcp   ESTAB      0      0         [2620:0:1003:416:a0ad:fd1a:62f:c862]:badport                       [2607:f8b0:400d:c0d::81]:5034                  timer:(keepalive,5.980ms,0) ino:6355539 sk:10f3d <->'
	echo 'tcp   ESTAB      0      0         [2620:0:1003:416:a0ad:fd1a:62f:c862]:58790                       [badip]:5034                  timer:(keepalive,5.980ms,0) ino:6355539 sk:10f3d <->'
	echo 'tcp   ESTAB      0      0         [2620:0:1003:416:a0ad:fd1a:62f:c862]:58790                       [2607:f8b0:400d:c0d::81]:5034                  timer:(keepalive,5.980ms,0) ino:6355539 sk:10f3d <->'
	`
	rtx.Must(ioutil.WriteFile(tmpdir+"/ss", []byte(fakeSS), 0777), "Could not create fake ss")

	defer func(s string) {
		*ssBinary = s
	}(*ssBinary)
	*ssBinary = tmpdir + "/ss"

	f := &ssFinder{}
	connections := f.GetConnections()
	if len(connections) != 1 {
		log.Println("We should have seen exactly one connection")
	}
}

type testTracer struct {
	calls   int
	answers []map[connection.Connection]struct{}
}

func (tt *testTracer) Trace(conn connection.Connection, t time.Time) string {
	return "Fake Trace test"
}

func (tt *testTracer) CreateCacheTest(conn connection.Connection, t time.Time, cachedTest string) {
	return
}

type testFinder struct {
}

func (tf *testFinder) GetConnections() map[connection.Connection]struct{} {
	conns := make(map[connection.Connection]struct{})
	return conns
}

func TestConnectionPollerConstruction(t *testing.T) {
	// The only thing we can verify by default is that the code does not crash.
	// Which is not nothing, but it's not a lot.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var tt testTracer
	cache := ipcache.New(ctx, &tt, time.Second, time.Second)
	connPoller := New(cache).(*connectionPoller)
	connPoller.finder = &testFinder{}
	connPoller.connectionPool = make(map[connection.Connection]struct{})
	conn1 := connection.Connection{
		RemoteIP:   "1.1.1.2",
		RemotePort: 5034,
		LocalIP:    "1.1.1.3",
		LocalPort:  58790,
		Cookie:     "10f3d"}
	connPoller.connectionPool[conn1] = struct{}{}
	connPoller.TraceClosedConnections()

	time.Sleep(200 * time.Millisecond)

	if connPoller.recentIPCache.GetCacheLength() != 1 {
		t.Errorf("ConnectionPoller not working properly")
	}
}
