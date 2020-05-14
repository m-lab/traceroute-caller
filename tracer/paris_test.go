package tracer

import (
	"io/ioutil"
	"strings"
	"testing"
	"time"

	"github.com/m-lab/uuid/prefix"

	"github.com/m-lab/go/rtx"
	"github.com/m-lab/traceroute-caller/connection"
)

func TestParis(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestParis")
	rtx.Must(err, "Could not create tempdir")

	p := &Paris{
		OutputPath: dir,
		Binary:     "echo",
		Timeout:    time.Duration(time.Hour),
	}

	// Test that it can perform a trace
	now := time.Date(2003, 11, 9, 15, 55, 59, 0, time.UTC)
	conn := connection.Connection{
		RemoteIP:   "10.1.1.1",
		RemotePort: 123,
		LocalIP:    "192.768.0.1",
		LocalPort:  456,
		Cookie:     "12AB",
	}
	p.DontTrace(conn, nil) // No crash == success

	// Test Trace
	out, err := p.Trace(conn, now)
	if err != nil {
		t.Error(err)
	}
	if strings.TrimSpace(out.Serialize()) != "--dst-port=123 --src-port=456 10.1.1.1" {
		t.Error("Bad output:", out.Serialize())
	}
	contents, err := ioutil.ReadFile(dir + "/2003/11/09/20031109T15:55:59Z-UUID-" + prefix.UnsafeString() + "_00000000000012AB.paris")
	rtx.Must(err, "Could not read file")
	if string(contents) != out.Serialize() {
		t.Error("The contents of the file should equal the returned values from scraper")
	}

	// Test a few error conditions.
	_, err = p.Trace(connection.Connection{Cookie: "this should be a number but is not"}, now)
	if err == nil {
		t.Error("Bad cookie should have caused an error")
	}

	p.Binary = "false"
	_, err = p.Trace(conn, now)
	if err == nil {
		t.Error("A failed call to the paris-traceroute binary should cause an error")
	}

	// Test that it can generate a trace from a cached trace, and that the file contents are the same.
	conn2 := connection.Connection{
		RemoteIP:   "10.1.1.1",
		RemotePort: 123,
		LocalIP:    "192.768.0.1",
		LocalPort:  789,
		Cookie:     "CDEF",
	}
	afterNow := time.Date(2003, 11, 9, 15, 58, 1, 0, time.UTC)
	p.TraceFromCachedTrace(conn2, afterNow, out)

	contents, err = ioutil.ReadFile(dir + "/2003/11/09/20031109T15:58:01Z-UUID-" + prefix.UnsafeString() + "_000000000000CDEF.cached.paris")
	rtx.Must(err, "Could not read file")
	if string(contents) != out.Serialize() {
		t.Error("The contents of the file should equal the returned values from the original trace")
	}

	// Now test some more error conditions
	err = p.TraceFromCachedTrace(connection.Connection{Cookie: "this should be a number but is not"}, afterNow, out)
	if err == nil {
		t.Error("Should not have been able to save with a bad cookie")
	}

	p.OutputPath = "/dev/null"
	p.Binary = "echo"
	_, err = p.Trace(conn, now)
	if err == nil {
		t.Error("You can't save data to /dev/null")
	}
	p.TraceFromCachedTrace(conn2, afterNow, out) // no crash == success

}
