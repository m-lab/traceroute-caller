package tracer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/m-lab/go/prometheusx"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/traceroute-caller/connection"
	"github.com/m-lab/uuid/prefix"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func TestScamper(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestScamper")
	rtx.Must(err, "failed to create tempdir")

	s := &Scamper{
		OutputPath:     dir,
		Binary:         "echo",
		ScamperTimeout: time.Duration(time.Hour),
		TracelbPTR:     true,
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
	if err != nil {
		t.Fatal(err)
	}
	uuid, err := conn.UUID()
	rtx.Must(err, "failed to make uuid")
	expected := `{"UUID":"` + uuid + `","TracerouteCallerVersion":"` + prometheusx.GitShortCommit + `","CachedResult":false,"CachedUUID":""}
-I tracelb -P icmp-echo -q 3 -W 0 -O ptr 10.1.1.1 -o- -O json
`
	if strings.TrimSpace(string(out)) != strings.TrimSpace(expected) {
		t.Error("Bad output:", string(out))
	}
	contents, err := ioutil.ReadFile(dir + "/2003/11/09/20031109T155559Z_" + prefix.UnsafeString() + "_00000000000012AB.jsonl")
	rtx.Must(err, "failed to read file")
	if string(contents) != string(out) {
		t.Error("The contents of the file should equal the returned values from scraper")
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

func TestTraceWritesMeta(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "TestTraceWritesUUID")
	rtx.Must(err, "failed to create tempdir")
	defer os.RemoveAll(tempdir)

	// Temporarily set the hostname to a value for testing.
	defer func(oldHn string) {
		hostname = oldHn
	}(hostname)
	hostname = "testhostname"

	s := &Scamper{
		Binary:         "echo",
		OutputPath:     tempdir,
		ScamperTimeout: 1 * time.Minute,
	}

	c := connection.Connection{
		Cookie:   "1",
		RemoteIP: "1.2.3.4",
	}

	faketime := time.Date(2019, time.April, 1, 3, 45, 51, 0, time.UTC)
	prometheusx.GitShortCommit = "Fake Version"
	_, err = s.Trace(c, faketime)

	if err != nil {
		t.Error("Trace not done correctly.")
	}
	// Unmarshal the first line of the output file.
	b, err := ioutil.ReadFile(tempdir + "/2019/04/01/20190401T034551Z_" + prefix.UnsafeString() + "_0000000000000001.jsonl")
	rtx.Must(err, "failed to read file")

	m := Metadata{}
	lines := strings.Split(string(b), "\n")
	if len(lines) < 2 {
		t.Error("Not enough lines in", lines)
	}
	rtx.Must(json.Unmarshal([]byte(lines[0]), &m), "failed to unmarshal")

	uuidChunks := strings.Split(m.UUID, "_")

	if uuidChunks[len(uuidChunks)-1] != "0000000000000001" {
		t.Error("Bad uuid:", m.UUID)
	}

	if m.TracerouteCallerVersion != "Fake Version" {
		t.Error("Bad traceroute caller version:", m.TracerouteCallerVersion)
	}
}

func TestTraceTimeout(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "TestTimeoutTrace")
	rtx.Must(err, "failed to create tempdir")
	defer os.RemoveAll(tempdir)

	s := &Scamper{
		Binary:         "yes",
		OutputPath:     tempdir,
		ScamperTimeout: 1 * time.Nanosecond,
	}

	defer func() {
		r := recover()
		if r != nil {
			t.Error("Should not trigger recovery:", err)
		}
	}()

	c := connection.Connection{
		Cookie:   "1",
		RemoteIP: "1.2.3.4",
	}

	faketime := time.Date(2019, time.April, 1, 3, 45, 51, 0, time.UTC)
	prometheusx.GitShortCommit = "Fake Version"
	_, err = s.Trace(c, faketime)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Error("Should return TimeOut err, not ", err)
	}
}

func TestCreateCacheTest(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "TestCachedTrace")
	rtx.Must(err, "failed to create tempdir")
	defer os.RemoveAll(tempdir)

	// Temporarily set the hostname to a value for testing.
	defer func(oldHn string) {
		hostname = oldHn
	}(hostname)
	hostname = "testhostname"

	s := &Scamper{
		Binary:         "echo",
		OutputPath:     tempdir,
		ScamperTimeout: 1 * time.Minute,
	}

	c := connection.Connection{
		Cookie:   "1",
		RemoteIP: "1.2.3.4",
	}

	faketime := time.Date(2019, time.April, 1, 3, 45, 51, 0, time.UTC)
	prometheusx.GitShortCommit = "Fake Version"
	cachedTest := []byte(`{"UUID": "ndt-plh7v_1566050090_000000000004D64D"}
	{"type":"cycle-start", "list_name":"/tmp/scamperctrl:51811", "id":1, "hostname":"ndt-plh7v", "start_time":1566691298}
	{"type":"tracelb", "version":"0.1", "userid":0, "method":"icmp-echo", "src":"::ffff:180.87.97.101", "dst":"::ffff:1.47.236.62", "start":{"sec":1566691298, "usec":476221, "ftime":"2019-08-25 00:01:38"}, "probe_size":60, "firsthop":1, "attempts":3, "confidence":95, "tos":0, "gaplimit":3, "wait_timeout":5, "wait_probe":250, "probec":0, "probec_max":3000, "nodec":0, "linkc":0}
	{"type":"cycle-stop", "list_name":"/tmp/scamperctrl:51811", "id":1, "hostname":"ndt-plh7v", "stop_time":1566691298}`)

	_ = s.TraceFromCachedTrace(c, faketime, []byte("Broken cached test"))
	_, errInvalidTest := ioutil.ReadFile(tempdir + "/2019/04/01/20190401T034551Z_" + prefix.UnsafeString() + "_0000000000000001.jsonl")
	if errInvalidTest == nil {
		t.Error("should fail to generate cached test")
	}

	_ = s.TraceFromCachedTrace(c, faketime, cachedTest)

	// Unmarshal the first line of the output file.
	b, err := ioutil.ReadFile(tempdir + "/2019/04/01/20190401T034551Z_" + prefix.UnsafeString() + "_0000000000000001.jsonl")
	rtx.Must(err, "failed to read file")

	m := Metadata{}
	lines := strings.Split(string(b), "\n")
	if len(lines) < 2 {
		t.Error("Not enough lines in", lines)
	}
	rtx.Must(json.Unmarshal([]byte(lines[0]), &m), "failed to unmarshal")

	uuidChunks := strings.Split(m.UUID, "_")

	if uuidChunks[len(uuidChunks)-1] != "0000000000000001" {
		t.Error("Bad uuid:", m.UUID)
	}

	if m.TracerouteCallerVersion != "Fake Version" {
		t.Error("Bad traceroute caller version:", m.TracerouteCallerVersion)
	}

	if m.CachedResult != true {
		t.Error("Bad traceroute CachedResult value:", m.CachedResult)
	}

	if m.CachedUUID != "ndt-plh7v_1566050090_000000000004D64D" {
		t.Error("Bad traceroute CachedUUID value:", m.CachedUUID)
	}

	// Now test an error condition.
	s.OutputPath = "/dev/null"
	if s.TraceFromCachedTrace(c, faketime, cachedTest) == nil {
		t.Error("Should have had a test failure trying to write to /dev/null")
	}
}

func TestExtractUUID(t *testing.T) {
	uuid := extractUUID([]byte("{\"UUID\": \"ndt-plh7v_1566050090_000000000004D64D\"}"))
	if uuid != "ndt-plh7v_1566050090_000000000004D64D" {
		t.Error("Fail to extract uuid")
	}

	failedUUID := extractUUID([]byte("invalid json"))
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
	if !bytes.Contains(meta, []byte("0000000000000ABC\",\"TracerouteCallerVersion\":\"Fake Version\",\"CachedResult\":true,\"CachedUUID\":\"00EF\"")) {
		t.Error("Fail to generate meta ", meta)
	}
}

func TestInvalidCookie(t *testing.T) {
	s := &Scamper{
		OutputPath: "/tmp",
	}
	c := connection.Connection{
		Cookie: "an invalid cookie",
	}
	if _, err := s.trace(c, time.Now()); err == nil {
		t.Error("Should have failed due to invalid cookie")
	}
	if err := s.TraceFromCachedTrace(c, time.Now(), nil); err == nil {
		t.Error("Should have failed due to invalid cookie")
	}
}
