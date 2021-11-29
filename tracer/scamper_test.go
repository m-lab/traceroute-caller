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
	"github.com/m-lab/uuid/prefix"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func TestTrace(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestScamper")
	rtx.Must(err, "failed to create tempdir")
	s := &Scamper{
		OutputPath:     dir,
		Binary:         "echo",
		ScamperTimeout: time.Duration(time.Hour),
		TracelbPTR:     true,
	}
	cookie := "12AB"
	now := time.Date(2003, 11, 9, 15, 55, 59, 0, time.UTC)
	out, err := s.Trace("10.1.1.1", cookie, "", now)
	if err != nil {
		t.Fatal(err)
	}
	wantOut := `{"UUID":"` + `","TracerouteCallerVersion":"` + prometheusx.GitShortCommit + `","CachedResult":false,"CachedUUID":""}
-I tracelb -P icmp-echo -q 3 -W 0 -O ptr 10.1.1.1 -o- -O json
`
	gotOut := string(out)
	if strings.TrimSpace(gotOut) != strings.TrimSpace(wantOut) {
		t.Errorf("Trace() = %q, want %q", strings.TrimSpace(gotOut), strings.TrimSpace(wantOut))
	}
	contents, err := ioutil.ReadFile(dir + "/2003/11/09/20031109T155559Z_" + prefix.UnsafeString() + "_00000000000012AB.jsonl")
	rtx.Must(err, "failed to read file")
	if string(contents) != gotOut {
		t.Errorf("contents = %q, want %q", string(contents), gotOut)
	}

	s.Binary = "false"
	_, err = s.Trace("10.1.1.1", cookie, "", now)
	if err == nil {
		t.Error("Trace() = nil, want error")
	}

	s.Binary = "yes"
	s.ScamperTimeout = time.Nanosecond
	_, err = s.Trace("10.1.1.1", cookie, "", now)
	if err == nil {
		t.Errorf("Trace() = %v, want nil", err)
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
	faketime := time.Date(2019, time.April, 1, 3, 45, 51, 0, time.UTC)
	prometheusx.GitShortCommit = "Fake Version"
	wantUUID := "0123456789"
	_, err = s.Trace("1.2.3.4", "1", wantUUID, faketime)
	if err != nil {
		t.Errorf("Trace() = %v, want nil", err)
	}

	// Unmarshal the first line of the output file.
	b, err := ioutil.ReadFile(tempdir + "/2019/04/01/20190401T034551Z_" + prefix.UnsafeString() + "_0000000000000001.jsonl")
	rtx.Must(err, "failed to read file")
	m := Metadata{}
	lines := strings.Split(string(b), "\n")
	if len(lines) < 2 {
		t.Errorf("len(lines) = %d, want 2", len(lines))
	}
	rtx.Must(json.Unmarshal([]byte(lines[0]), &m), "failed to unmarshal")
	uuidChunks := strings.Split(m.UUID, "_")
	if gotUUID := uuidChunks[len(uuidChunks)-1]; gotUUID != wantUUID {
		t.Errorf("got UUID %q, want %q", gotUUID, wantUUID)
	}
	if m.TracerouteCallerVersion != "Fake Version" {
		t.Errorf("got traceroute caller version %q, want %q", m.TracerouteCallerVersion, "Fake Version")
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
			t.Errorf("recover() = %v, want nil (error: %v)", r, err)
		}
	}()

	faketime := time.Date(2019, time.April, 1, 3, 45, 51, 0, time.UTC)
	prometheusx.GitShortCommit = "Fake Version"
	_, err = s.Trace("1.2.3.4", "1", "", faketime)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Trace() = %v, want %v", err, context.DeadlineExceeded)
	}
}

func TestTraceFromCachedTrace(t *testing.T) {
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

	faketime := time.Date(2019, time.April, 1, 3, 45, 51, 0, time.UTC)
	prometheusx.GitShortCommit = "Fake Version"
	cachedTest := []byte(`{"UUID": "ndt-plh7v_1566050090_000000000004D64D"}
	{"type":"cycle-start", "list_name":"/tmp/scamperctrl:51811", "id":1, "hostname":"ndt-plh7v", "start_time":1566691298}
	{"type":"tracelb", "version":"0.1", "userid":0, "method":"icmp-echo", "src":"::ffff:180.87.97.101", "dst":"::ffff:1.47.236.62", "start":{"sec":1566691298, "usec":476221, "ftime":"2019-08-25 00:01:38"}, "probe_size":60, "firsthop":1, "attempts":3, "confidence":95, "tos":0, "gaplimit":3, "wait_timeout":5, "wait_probe":250, "probec":0, "probec_max":3000, "nodec":0, "linkc":0}
	{"type":"cycle-stop", "list_name":"/tmp/scamperctrl:51811", "id":1, "hostname":"ndt-plh7v", "stop_time":1566691298}`)

	_ = s.TraceFromCachedTrace("ndt-plh7v_1566050090_000000000004D64D", "1", faketime, []byte("Broken cached test"))
	_, errInvalidTest := ioutil.ReadFile(tempdir + "/2019/04/01/20190401T034551Z_" + prefix.UnsafeString() + "_0000000000000001.jsonl")
	if errInvalidTest == nil {
		t.Error("TraceFromCachedTrace() = nil, want error")
	}

	_ = s.TraceFromCachedTrace("ndt-plh7v_1566050090_000000000004D64D", "1", faketime, cachedTest)
	// Unmarshal the first line of the output file.
	b, err := ioutil.ReadFile(tempdir + "/2019/04/01/20190401T034551Z_" + prefix.UnsafeString() + "_0000000000000001.jsonl")
	rtx.Must(err, "failed to read file")
	m := Metadata{}
	lines := strings.Split(string(b), "\n")
	if len(lines) < 2 {
		t.Errorf("len(lines) = %d, want 2", len(lines))
	}
	rtx.Must(json.Unmarshal([]byte(lines[0]), &m), "failed to unmarshal")

	wantUUID := "000000000004D64D"
	uuidChunks := strings.Split(m.UUID, "_")
	if gotUUID := uuidChunks[len(uuidChunks)-1]; gotUUID != wantUUID {
		t.Errorf("got UUID %q, want %q", gotUUID, wantUUID)
	}
	if m.TracerouteCallerVersion != "Fake Version" {
		t.Errorf("got traceroute caller version %q, want %q", m.TracerouteCallerVersion, "Fake Version")
	}
	if m.CachedResult != true {
		t.Errorf("got cached result %v, want true", m.CachedResult)
	}
	wantUUID = "ndt-plh7v_1566050090_000000000004D64D"
	if m.CachedUUID != "ndt-plh7v_1566050090_000000000004D64D" {
		t.Errorf("got cached UUID %q, want %q", m.CachedUUID, wantUUID)
	}

	// Now test an error condition.
	s.OutputPath = "/dev/null"
	if s.TraceFromCachedTrace("ndt-plh7v_1566050090_000000000004D64D", "1", faketime, cachedTest) == nil {
		t.Error("TraceFromCachedTrace() = nil, want error")
	}
}

func TestExtractUUID(t *testing.T) {
	uuid := extractUUID([]byte("{\"UUID\": \"ndt-plh7v_1566050090_000000000004D64D\"}"))
	if uuid != "ndt-plh7v_1566050090_000000000004D64D" {
		t.Error("Fail to extract uuid")
	}

	failedUUID := extractUUID([]byte("invalid json"))
	if failedUUID != "" {
		t.Errorf("failedUUID = %q, want \"\"", failedUUID)
	}
}

func TestDontTrace(t *testing.T) {
	s := &Scamper{
		OutputPath: "/tmp",
	}
	s.DontTrace()
}

func TestCreateMetaline(t *testing.T) {
	prometheusx.GitShortCommit = "Fake Version"
	gotMeta := createMetaline("0000000000000ABC", true, "00EF")
	wantMeta := []byte("0000000000000ABC\",\"TracerouteCallerVersion\":\"Fake Version\",\"CachedResult\":true,\"CachedUUID\":\"00EF\"")
	if !bytes.Contains(gotMeta, wantMeta) {
		t.Errorf("gotMeta %q does not contain wantMeta %q", gotMeta, wantMeta)
	}
}

func TestInvalidCookie(t *testing.T) {
	s := &Scamper{
		OutputPath: "/tmp",
	}
	if _, err := s.Trace("10.1.1.1", "an invalid cookie", "", time.Now()); err == nil {
		t.Error("Trace() = nil, want error")
	}
	if err := s.TraceFromCachedTrace("", "an invalid cookie", time.Now(), nil); err == nil {
		t.Error("TraceFromCachedTrace() = nil, want error")
	}
}
