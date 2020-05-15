package tracer

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/m-lab/go/prometheusx"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/go/warnonerror"
	"github.com/m-lab/traceroute-caller/connection"
	"github.com/m-lab/traceroute-caller/ipcache"
	"github.com/m-lab/traceroute-caller/schema"
	"github.com/m-lab/uuid-annotator/asnannotator"
	"github.com/m-lab/uuid-annotator/geoannotator"
	"github.com/m-lab/uuid-annotator/ipservice"
	"github.com/m-lab/uuid/prefix"
)

func TestScamper(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestScamper")
	rtx.Must(err, "Could not create tempdir")

	s := &Scamper{
		OutputPath:     dir,
		Binary:         "echo",
		ScamperTimeout: time.Duration(time.Hour),
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
	s.DontTrace(conn, nil) // No crash == success

	// Test Trace
	out, err := s.Trace(conn, now)
	if err == nil || err.Error() != "Invalid test" {
		t.Error("The faked test should fail the parsing for annotation")
	}

	if out != nil {
		t.Error("Should return empty output")
	}

	s.Binary = "false"
	_, err = s.Trace(conn, now)
	if err == nil {
		t.Error("A failed call to the scamper binary should cause an error")
	}

	s.Binary = "yes"
	s.ScamperTimeout = time.Nanosecond
	_, err = s.Trace(conn, now)
	if err == nil {
		t.Error("A timed-out call to the scamper binary should cause an error")
	}
}

func TestCancelStopsDaemon(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "CancelStopsDaemon")
	rtx.Must(err, "Could not create tempdir")
	defer os.RemoveAll(tempdir)
	d := ScamperDaemon{
		// Let the shell use the path to discover these.
		Scamper: &Scamper{
			Binary:         "scamper",
			OutputPath:     tempdir,
			ScamperTimeout: 1 * time.Minute,
		},
		AttachBinary:     "sc_attach",
		Warts2JSONBinary: "sc_warts2json",
		ControlSocket:    tempdir + "/ctrl",
	}
	d.DontTrace(connection.Connection{}, errors.New(""))
	ctx, cancel := context.WithCancel(context.Background())
	wg := sync.WaitGroup{}
	wg.Add(1)
	done := false
	go func() {
		time.Sleep(time.Duration(100 * time.Millisecond))
		log.Println("Starting the daemon")
		d.MustStart(ctx)
		done = true
		wg.Done()
	}()
	log.Println("About to sleep")

	time.Sleep(time.Duration(200 * time.Millisecond))
	if done {
		t.Error("The function should not be done yet.")
	}
	log.Println("About to cancel()")
	cancel()
	wg.Wait()
	if !done {
		t.Error("wg.Done() but done is still false")
	}
}

func TestExistingFileStopsDaemonCreation(t *testing.T) {
	// This test verifies that, when the indicated control socket already exists on
	// the file system, the Daemon.MustStart function calls log.Fatal. The control
	// socket needs to exist in a well-known location. If there is already a file
	// in that well-known location, then that is an indication that something has
	// gone wrong with the surrounding environment.

	defer func() {
		logFatal = log.Fatal
	}()
	logFatal = func(args ...interface{}) {
		panic("An error for testing")
	}

	tempdir, err := ioutil.TempDir("", "TestExistingFileStopsDaemonCreation")
	rtx.Must(err, "Could not create tempdir")
	defer os.RemoveAll(tempdir)
	rtx.Must(ioutil.WriteFile(tempdir+"/ctrl", []byte("test"), 0666), "Could not create file")
	d := ScamperDaemon{
		// Let the shell use the path to discover these.
		Scamper: &Scamper{
			Binary:         "scamper",
			OutputPath:     tempdir,
			ScamperTimeout: 1 * time.Minute,
		},
		AttachBinary:     "sc_attach",
		Warts2JSONBinary: "sc_warts2json",
		ControlSocket:    tempdir + "/ctrl",
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Error("This was supposed to cause a panic")
		}
	}()

	d.MustStart(context.Background())
}

func TestTraceWritesMeta(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "TestTraceWritesUUID")
	rtx.Must(err, "Could not create tempdir")
	defer os.RemoveAll(tempdir)

	// Temporarily set the hostname to a value for testing.
	defer func(oldHn string) {
		hostname = oldHn
	}(hostname)
	hostname = "testhostname"

	d := ScamperDaemon{
		Scamper: &Scamper{
			OutputPath:     tempdir,
			ScamperTimeout: 1 * time.Minute,
		},
		AttachBinary:     "echo",
		Warts2JSONBinary: "cat",
	}

	c := connection.Connection{
		Cookie:   "1",
		RemoteIP: "1.2.3.4",
	}

	faketime := time.Date(2019, time.April, 1, 3, 45, 51, 0, time.UTC)
	prometheusx.GitShortCommit = "Fake Version"
	_, err = d.Trace(c, faketime)

	if err == nil || err.Error() != "Invalid test" {
		t.Error("Trace should fail with meta line only.")
	}
}

func TestTraceTimeout(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "TestTimeoutTrace")
	rtx.Must(err, "Could not create tempdir")
	defer os.RemoveAll(tempdir)

	d := ScamperDaemon{
		Scamper: &Scamper{
			OutputPath:     tempdir,
			ScamperTimeout: 1 * time.Nanosecond,
		},
		AttachBinary:     "yes",
		Warts2JSONBinary: "cat",
	}

	defer func() {
		r := recover()
		if r == nil {
			log.Println("Correct. timeout error should NOT trigger recover.")
		}
	}()

	c := connection.Connection{
		Cookie:   "1",
		RemoteIP: "1.2.3.4",
	}

	faketime := time.Date(2019, time.April, 1, 3, 45, 51, 0, time.UTC)
	prometheusx.GitShortCommit = "Fake Version"
	data, err := d.Trace(c, faketime)
	if err.Error() != "timeout" {
		t.Error("Should return TimeOut err, not ", err)
	}
	if len(data.Serialize()) != 0 {
		t.Error("Should return empty string when TimeOut")
	}
}

func TestCreateCacheTest(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "TestCachedTrace")
	rtx.Must(err, "Could not create tempdir")
	defer os.RemoveAll(tempdir)

	// Temporarily set the hostname to a value for testing.
	defer func(oldHn string) {
		hostname = oldHn
	}(hostname)
	hostname = "testhostname"

	d := ScamperDaemon{
		Scamper: &Scamper{
			OutputPath:     tempdir,
			ScamperTimeout: 1 * time.Minute,
		},
		AttachBinary:     "echo",
		Warts2JSONBinary: "cat",
	}

	c := connection.Connection{
		Cookie:   "1",
		RemoteIP: "1.2.3.4",
	}

	faketime := time.Date(2019, time.April, 1, 3, 45, 51, 0, time.UTC)
	prometheusx.GitShortCommit = "Fake Version"
	cachedTest := schema.PTTestRaw{
		UUID:           "ndt-plh7v_1566050090_000000000004D64D",
		ScamperVersion: "0.1",
	}

	var pt schema.PTTestRaw
	d.TraceFromCachedTrace(c, faketime, &ScamperData{data: pt})
	_, errInvalidTest := ioutil.ReadFile(tempdir + "/2019/04/01/20190401T034551Z_" + prefix.UnsafeString() + "_0000000000000001.jsonl")
	if errInvalidTest == nil {
		t.Error("should fail to generate cached test")
	}

	d.TraceFromCachedTrace(c, faketime, &ScamperData{data: cachedTest})

	// Unmarshal the first line of the output file.
	b, err := ioutil.ReadFile(tempdir + "/2019/04/01/20190401T034551Z_" + prefix.UnsafeString() + "_0000000000000001.json")
	rtx.Must(err, "Could not read file")

	m := schema.PTTestRaw{}

	rtx.Must(json.Unmarshal([]byte(b), &m), "Could not unmarshal")

	uuidChunks := strings.Split(m.UUID, "_")

	if uuidChunks[len(uuidChunks)-1] != "0000000000000001" {
		t.Error("Bad uuid:", m.UUID)
	}

	if m.ScamperVersion != "0.1" {
		t.Error("Bad traceroute caller version:", m.ScamperVersion)
	}

	if m.CachedResult != true {
		t.Error("Bad traceroute CachedResult value:", m.CachedResult)
	}

	// Now test an error condition.
	d.OutputPath = "/dev/null"
	if d.TraceFromCachedTrace(c, faketime, &ScamperData{data: cachedTest}) == nil {
		t.Error("Should have had a test failure trying to write to /dev/null")
	}
}

func TestRecovery(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "TestRecovery")
	rtx.Must(err, "Could not create tempdir")
	defer os.RemoveAll(tempdir)

	// Temporarily set the hostname to a value for testing.
	defer func(oldHn string) {
		hostname = oldHn
	}(hostname)
	hostname = "testhostname"

	d := ScamperDaemon{
		Scamper: &Scamper{
			OutputPath:     tempdir,
			ScamperTimeout: 1 * time.Minute,
		},
		AttachBinary:     "echo",
		Warts2JSONBinary: "cat",
	}

	c := connection.Connection{
		Cookie: "not a number in base 16 at all",
	}

	// Run both trace methods.
	d.TraceAll([]connection.Connection{c})
	d.Trace(c, time.Now())
	// If this doesn't crash, then the recovery process works!
}

func TestExtractUUID(t *testing.T) {
	uuid := extractUUID("{\"UUID\": \"ndt-plh7v_1566050090_000000000004D64D\"}")
	if uuid != "ndt-plh7v_1566050090_000000000004D64D" {
		t.Error("Fail to extract uuid")
	}

	failedUUID := extractUUID("invalid json")
	if failedUUID != "" {
		t.Error("Should fail to extract uuid")
	}
}

func TestGetMetaline(t *testing.T) {
	conn := connection.Connection{
		RemoteIP:   "1.1.1.2",
		RemotePort: 123,
		LocalIP:    "1.1.1.3",
		LocalPort:  345,
		Cookie:     "abc",
	}
	prometheusx.GitShortCommit = "Fake Version"
	meta := GetMetaline(conn, true, "00EF")
	if !strings.Contains(meta, "0000000000000ABC\",\"TracerouteCallerVersion\":\"Fake Version\",\"CachedResult\":true,\"CachedUUID\":\"00EF\"") {
		t.Error("Fail to generate meta ", meta)
	}
}

// If this successfully compiles, then ScamperDaemon implements the Tracer interface,
// which is what we want it to do.
func assertScamperDaemonIsTracer(d *ScamperDaemon) {
	func(t ipcache.Tracer) {}(d)
}

func TestAnnotateHops(t *testing.T) {
	// Test IP service not exist
	var hops []schema.ScamperHop
	hops = append(hops, schema.ScamperHop{
		Source: schema.HopIP{IP: "1.2.3.4"},
	})
	hops = append(hops, schema.ScamperHop{
		Source: schema.HopIP{IP: "1.47.236.62"},
	})
	pt := schema.PTTestRaw{
		Hop: hops,
	}
	scamperData := &ScamperData{data: pt}
	client := ipservice.NewClient("")
	err := scamperData.AnnotateHops(client)
	if err != nil {
		t.Error("Should not fail with IP service not exist at all")
	}

	// Create fake service
	dir, err := ioutil.TempDir("", "ExampleFakeServerForTesting")
	rtx.Must(err, "could not create tempdir")
	defer os.RemoveAll(dir)

	*ipservice.SocketFilename = dir + "/ipservice.sock"
	srv, err := ipservice.NewServer(*ipservice.SocketFilename,
		asnannotator.NewFake(),
		geoannotator.NewFake())
	rtx.Must(err, "Could not create server")
	defer warnonerror.Close(srv, "Could not stop the server")

	go srv.Serve()

	client2 := ipservice.NewClient(*ipservice.SocketFilename)
	scamperData2 := &ScamperData{data: pt}
	err = scamperData2.AnnotateHops(client2)

	if err != nil {
		t.Error("Should succeed here")
	}
	// Notice that "asn" is 5 for IP "1.2.3.4"
	expectedOutput := `{"schema_version":"\"\"","uuid":"\"\"","testtime":"0001-01-01T00:00:00Z","start_time":0,"stop_time":0,"scamper_version":"\"\"","serverIP":"\"\"","clientIP":"\"\"","probe_size":0,"probec":0,"hop":[{"source":{"ip":"\"1.2.3.4\"","hostname":"\"\"","geo":{"Missing":true},"network":{"CIDR":"1.2.3.4/32","ASNumber":5,"ASName":"Test Number Five","Systems":[{"ASNs":[5]}]}},"linkc":0,"link":null},{"source":{"ip":"\"1.47.236.62\"","hostname":"\"\"","geo":{"Missing":true},"network":{"Missing":true}},"linkc":0,"link":null}],"cached_result":false,"cached_uuid":"\"\"","traceroutecaller_commit":"\"\""}`
	if scamperData2.Serialize() != string(expectedOutput) {
		t.Error("Fail to add annotation.")
	}
}
