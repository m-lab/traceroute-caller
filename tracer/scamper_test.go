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

	"github.com/m-lab/etl/schema"
	"github.com/m-lab/go/prometheusx"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/go/warnonerror"
	"github.com/m-lab/traceroute-caller/connection"
	"github.com/m-lab/traceroute-caller/ipcache"
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
	cachedTest := `{"uuid":"\"ndt-plh7v_1566050090_000000000004D64D\"","testtime":"0001-01-01T00:00:00Z","parseinfo":{"TaskFileName":"","ParseTime":"0001-01-01T00:00:00Z","ParserVersion":"","Filename":""},"start_time":1566691298,"stop_time":1566691298,"scamper_version":"\"0.1\"","source":{"IP":"::ffff:180.87.97.101","Port":0,"IATA":"","Geo":null,"Network":null},"destination":{"IP":"::ffff:1.47.236.62","Port":0,"Geo":null,"Network":null},"probe_size":60,"probec":0,"hop":null,"exp_version":"\"\"","cached_result":false}`

	d.TraceFromCachedTrace(c, faketime, &ScamperData{data: []byte(`Broken cached test`)})
	_, errInvalidTest := ioutil.ReadFile(tempdir + "/2019/04/01/20190401T034551Z_" + prefix.UnsafeString() + "_0000000000000001.jsonl")
	if errInvalidTest == nil {
		t.Error("should fail to generate cached test")
	}

	d.TraceFromCachedTrace(c, faketime, &ScamperData{data: []byte(cachedTest)})

	// Unmarshal the first line of the output file.
	b, err := ioutil.ReadFile(tempdir + "/2019/04/01/20190401T034551Z_" + prefix.UnsafeString() + "_0000000000000001.json")
	rtx.Must(err, "Could not read file")

	m := schema.PTTest{}

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
	if d.TraceFromCachedTrace(c, faketime, &ScamperData{data: []byte(cachedTest)}) == nil {
		t.Error("Should have had a test failure tryin gto write to /dev/null")
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
	testStr := `{"UUID": "ndt-plh7v_1566050090_000000000004D60F"}
	{"type":"cycle-start", "list_name":"/tmp/scamperctrl:51803", "id":1, "hostname":"ndt-plh7v", "start_time":1566691268}
	{"type":"tracelb", "version":"0.1", "userid":0, "method":"icmp-echo", "src":"2001:550:1b01:1:e41d:2d00:151:f6c0", "dst":"2600:1009:b013:1a59:c369:b528:98fd:ab43", "start":{"sec":1567900908, "usec":729543, "ftime":"2019-09-08 00:01:48"}, "probe_size":60, "firsthop":1, "attempts":3, "confidence":95, "tos":0, "gaplimit":3, "wait_timeout":5, "wait_probe":250, "probec":85, "probec_max":3000, "nodec":6, "linkc":6, "nodes":[{"addr":"1.2.3.4", "q_ttl":1, "linkc":1, "links":[[{"addr":"2001:550:3::1ca", "probes":[{"tx":{"sec":1567900908, "usec":979595}, "replyc":1, "ttl":2, "attempt":0, "flowid":1, "replies":[{"rx":{"sec":1567900909, "usec":16398}, "ttl":63, "rtt":36.803, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900909, "usec":229642}, "replyc":1, "ttl":2, "attempt":0, "flowid":2, "replies":[{"rx":{"sec":1567900909, "usec":229974}, "ttl":63, "rtt":0.332, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900909, "usec":480242}, "replyc":1, "ttl":2, "attempt":0, "flowid":3, "replies":[{"rx":{"sec":1567900909, "usec":480571}, "ttl":63, "rtt":0.329, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900909, "usec":730987}, "replyc":1, "ttl":2, "attempt":0, "flowid":4, "replies":[{"rx":{"sec":1567900909, "usec":731554}, "ttl":63, "rtt":0.567, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900909, "usec":982029}, "replyc":1, "ttl":2, "attempt":0, "flowid":5, "replies":[{"rx":{"sec":1567900909, "usec":982358}, "ttl":63, "rtt":0.329, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900910, "usec":232994}, "replyc":1, "ttl":2, "attempt":0, "flowid":6, "replies":[{"rx":{"sec":1567900910, "usec":234231}, "ttl":63, "rtt":1.237, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]}]}]]},{"addr":"2001:550:3::1ca", "q_ttl":1, "linkc":1, "links":[[{"addr":"2600:803::79", "probes":[{"tx":{"sec":1567900910, "usec":483606}, "replyc":1, "ttl":3, "attempt":0, "flowid":1, "replies":[{"rx":{"sec":1567900910, "usec":500939}, "ttl":58, "rtt":17.333, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900910, "usec":734394}, "replyc":1, "ttl":3, "attempt":0, "flowid":2, "replies":[{"rx":{"sec":1567900910, "usec":752612}, "ttl":58, "rtt":18.218, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900910, "usec":985425}, "replyc":1, "ttl":3, "attempt":0, "flowid":3, "replies":[{"rx":{"sec":1567900911, "usec":6498}, "ttl":58, "rtt":21.073, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900911, "usec":235481}, "replyc":1, "ttl":3, "attempt":0, "flowid":4, "replies":[{"rx":{"sec":1567900911, "usec":252800}, "ttl":58, "rtt":17.319, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900911, "usec":486164}, "replyc":1, "ttl":3, "attempt":0, "flowid":5, "replies":[{"rx":{"sec":1567900911, "usec":503522}, "ttl":58, "rtt":17.358, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900911, "usec":737096}, "replyc":1, "ttl":3, "attempt":0, "flowid":6, "replies":[{"rx":{"sec":1567900911, "usec":760439}, "ttl":58, "rtt":23.343, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]}]}]]},{"addr":"2600:803::79", "q_ttl":1, "linkc":1, "links":[[{"addr":"2600:803:150f::4a", "probes":[{"tx":{"sec":1567900911, "usec":987801}, "replyc":1, "ttl":4, "attempt":0, "flowid":1, "replies":[{"rx":{"sec":1567900912, "usec":10282}, "ttl":57, "rtt":22.481, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900912, "usec":238227}, "replyc":1, "ttl":4, "attempt":0, "flowid":2, "replies":[{"rx":{"sec":1567900912, "usec":262270}, "ttl":57, "rtt":24.043, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900912, "usec":539699}, "replyc":1, "ttl":4, "attempt":0, "flowid":3, "replies":[{"rx":{"sec":1567900912, "usec":562078}, "ttl":57, "rtt":22.379, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900912, "usec":789753}, "replyc":1, "ttl":4, "attempt":0, "flowid":4, "replies":[{"rx":{"sec":1567900912, "usec":812145}, "ttl":57, "rtt":22.392, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900913, "usec":42261}, "replyc":1, "ttl":4, "attempt":0, "flowid":5, "replies":[{"rx":{"sec":1567900913, "usec":64678}, "ttl":57, "rtt":22.417, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900913, "usec":292682}, "replyc":1, "ttl":4, "attempt":0, "flowid":6, "replies":[{"rx":{"sec":1567900913, "usec":315254}, "ttl":57, "rtt":22.572, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]}]}]]},{"addr":"2600:803:150f::4a", "q_ttl":1, "linkc":1, "links":[[{"addr":"2001:4888:36:1002:3a2:1:0:1", "probes":[{"tx":{"sec":1567900913, "usec":543335}, "replyc":1, "ttl":5, "attempt":0, "flowid":1, "replies":[{"rx":{"sec":1567900913, "usec":568980}, "ttl":56, "rtt":25.645, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900913, "usec":793793}, "replyc":1, "ttl":5, "attempt":0, "flowid":2, "replies":[{"rx":{"sec":1567900913, "usec":816848}, "ttl":56, "rtt":23.055, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900914, "usec":43821}, "replyc":1, "ttl":5, "attempt":0, "flowid":3, "replies":[{"rx":{"sec":1567900914, "usec":72827}, "ttl":56, "rtt":29.006, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900914, "usec":294820}, "replyc":1, "ttl":5, "attempt":0, "flowid":4, "replies":[{"rx":{"sec":1567900914, "usec":320815}, "ttl":56, "rtt":25.995, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900914, "usec":545802}, "replyc":1, "ttl":5, "attempt":0, "flowid":5, "replies":[{"rx":{"sec":1567900914, "usec":568924}, "ttl":56, "rtt":23.122, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900914, "usec":796839}, "replyc":1, "ttl":5, "attempt":0, "flowid":6, "replies":[{"rx":{"sec":1567900914, "usec":824735}, "ttl":56, "rtt":27.896, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]}]}]]},{"addr":"2001:4888:36:1002:3a2:1:0:1", "q_ttl":1, "linkc":1, "links":[[{"addr":"2001:4888:3f:6092:3a2:26:0:1", "probes":[{"tx":{"sec":1567900915, "usec":46897}, "replyc":1, "ttl":6, "attempt":0, "flowid":1, "replies":[{"rx":{"sec":1567900915, "usec":69996}, "ttl":245, "rtt":23.099, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900915, "usec":297455}, "replyc":1, "ttl":6, "attempt":0, "flowid":2, "replies":[{"rx":{"sec":1567900915, "usec":320524}, "ttl":245, "rtt":23.069, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900915, "usec":547737}, "replyc":1, "ttl":6, "attempt":0, "flowid":3, "replies":[{"rx":{"sec":1567900915, "usec":570899}, "ttl":245, "rtt":23.162, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900915, "usec":798167}, "replyc":1, "ttl":6, "attempt":0, "flowid":4, "replies":[{"rx":{"sec":1567900915, "usec":821218}, "ttl":245, "rtt":23.051, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900916, "usec":55367}, "replyc":1, "ttl":6, "attempt":0, "flowid":5, "replies":[{"rx":{"sec":1567900916, "usec":78485}, "ttl":245, "rtt":23.118, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]},{"tx":{"sec":1567900916, "usec":306410}, "replyc":1, "ttl":6, "attempt":0, "flowid":6, "replies":[{"rx":{"sec":1567900916, "usec":329419}, "ttl":245, "rtt":23.009, "icmp_type":3, "icmp_code":0, "icmp_q_tos":0, "icmp_q_ttl":1}]}]}]]},{"addr":"2001:4888:3f:6092:3a2:26:0:1", "q_ttl":1, "linkc":1}]}
	{"type":"cycle-stop", "list_name":"/tmp/scamperctrl:51803", "id":1, "hostname":"ndt-plh7v", "stop_time":1566691541}
	`

	scamperData := &ScamperData{data: []byte(testStr)}
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
	scamperData2 := &ScamperData{data: []byte(testStr)}
	err = scamperData2.AnnotateHops(client2)

	if err != nil {
		t.Error("Should succeed here")
	}
	// Notice that "asn" is 5 for IP "1.2.3.4"
	expectedOutput := `{"schema_version":"\"1\"","uuid":"\"ndt-plh7v_1566050090_000000000004D60F\"","testtime":"0001-01-01T00:00:00Z","start_time":1566691268,"stop_time":1566691541,"scamper_version":"\"0.1\"","serverIP":"\"2001:550:1b01:1:e41d:2d00:151:f6c0\"","clientIP":"\"2600:1009:b013:1a59:c369:b528:98fd:ab43\"","probe_size":60,"probec":85,"hop":[{"source":{"ip":"\"1.2.3.4\"","city":"\"\"","country_code":"\"\"","hostname":"\"\"","asn":5},"linkc":1,"link":[{"hop_dst_ip":"\"2001:550:3::1ca\"","ttl":2,"probes":[{"flowid":1,"rtt":[36.803]},{"flowid":2,"rtt":[0.332]},{"flowid":3,"rtt":[0.329]},{"flowid":4,"rtt":[0.567]},{"flowid":5,"rtt":[0.329]},{"flowid":6,"rtt":[1.237]}]}]},{"source":{"ip":"\"2001:550:3::1ca\"","city":"\"\"","country_code":"\"\"","hostname":"\"\"","asn":0},"linkc":1,"link":[{"hop_dst_ip":"\"2600:803::79\"","ttl":3,"probes":[{"flowid":1,"rtt":[17.333]},{"flowid":2,"rtt":[18.218]},{"flowid":3,"rtt":[21.073]},{"flowid":4,"rtt":[17.319]},{"flowid":5,"rtt":[17.358]},{"flowid":6,"rtt":[23.343]}]}]},{"source":{"ip":"\"2600:803::79\"","city":"\"\"","country_code":"\"\"","hostname":"\"\"","asn":0},"linkc":1,"link":[{"hop_dst_ip":"\"2600:803:150f::4a\"","ttl":4,"probes":[{"flowid":1,"rtt":[22.481]},{"flowid":2,"rtt":[24.043]},{"flowid":3,"rtt":[22.379]},{"flowid":4,"rtt":[22.392]},{"flowid":5,"rtt":[22.417]},{"flowid":6,"rtt":[22.572]}]}]},{"source":{"ip":"\"2600:803:150f::4a\"","city":"\"\"","country_code":"\"\"","hostname":"\"\"","asn":0},"linkc":1,"link":[{"hop_dst_ip":"\"2001:4888:36:1002:3a2:1:0:1\"","ttl":5,"probes":[{"flowid":1,"rtt":[25.645]},{"flowid":2,"rtt":[23.055]},{"flowid":3,"rtt":[29.006]},{"flowid":4,"rtt":[25.995]},{"flowid":5,"rtt":[23.122]},{"flowid":6,"rtt":[27.896]}]}]},{"source":{"ip":"\"2001:4888:36:1002:3a2:1:0:1\"","city":"\"\"","country_code":"\"\"","hostname":"\"\"","asn":0},"linkc":1,"link":[{"hop_dst_ip":"\"2001:4888:3f:6092:3a2:26:0:1\"","ttl":6,"probes":[{"flowid":1,"rtt":[23.099]},{"flowid":2,"rtt":[23.069]},{"flowid":3,"rtt":[23.162]},{"flowid":4,"rtt":[23.051]},{"flowid":5,"rtt":[23.118]},{"flowid":6,"rtt":[23.009]}]}]},{"source":{"ip":"\"2001:4888:3f:6092:3a2:26:0:1\"","city":"\"\"","country_code":"\"\"","hostname":"\"\"","asn":0},"linkc":1,"link":null}],"cached_result":false,"cached_uuid":"\"\"","traceroutecaller_commit":"\"\""}`
	if scamperData2.Serialize() != string(expectedOutput) {
		t.Error("Fail to add annotation.")
	}
}
