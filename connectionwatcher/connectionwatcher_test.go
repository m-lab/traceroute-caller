// The package is not connectionwatcher_test for test unexported funcs
package connectionwatcher

import (
	"log"
	"reflect"
	"testing"

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

	_, _, err = parseIPAndPort("not an address at all")
	if err == nil {
		log.Println("Should have had an error on bad input")
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

func TestConnectionWatcherConstruction(t *testing.T) {
	// The only thing we can verify by default is that the code does not crash.
	// Which is not nothing, but it's not a lot.
	connWatcher := New()
	connWatcher.GetClosedCollection()
}

type testFinder struct {
	calls   int
	answers []map[connection.Connection]struct{}
}

func (tf *testFinder) GetConnections() map[connection.Connection]struct{} {
	calls := tf.calls
	tf.calls++
	return tf.answers[calls]
}

func TestGetClosedCollection(t *testing.T) {
	// This setup causes both conn3 and conn2 to disappear, but because conn3 is in
	// the ipcache, only conn2 should be returned.
	connWatcher := New().(*connectionWatcher)
	conn1 := connection.Connection{RemoteIP: "1.1.1.1"}
	conn2 := connection.Connection{RemoteIP: "1.1.1.2"}
	conn3 := connection.Connection{RemoteIP: "1.1.1.3"}
	connWatcher.recentIPCache.Add(conn3.RemoteIP)
	connWatcher.finder = &testFinder{
		answers: []map[connection.Connection]struct{}{
			{conn1: struct{}{}, conn2: struct{}{}, conn3: struct{}{}},
			{conn1: struct{}{}},
		},
	}
	connWatcher.connectionPool = connWatcher.GetConnections()

	c := connWatcher.GetClosedCollection()

	if len(c) != 1 || c[0] != conn2 {
		t.Errorf("Wanted %v but got %v", []connection.Connection{conn2}, c)
	}
}
