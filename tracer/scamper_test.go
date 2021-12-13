package tracer

import (
	"bytes"
	"encoding/json"
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
	if err != nil {
		t.Fatal(err)
	}
	cookie := "12AB"
	now := time.Date(2003, 11, 9, 15, 55, 59, 0, time.UTC)
	path := dir + "/2003/11/09/20031109T155559Z_" + prefix.UnsafeString() + "_00000000000012AB.jsonl"

	tests := []struct {
		binary     string
		traceType  string
		noArgs     bool
		shouldFail bool
		want       string
	}{
		{"false", "mda", true, true, ""},
		{"yes", "mda", true, true, ""},
		{"echo", "mda", false, false, `{"UUID":"","TracerouteCallerVersion":"` + prometheusx.GitShortCommit + `","CachedTrace":false,"CachedUUID":""}
-o- -O json -I tracelb -P icmp-echo -q 3 -W 39 -O ptr 10.1.1.1`},
	}
	for _, test := range tests {
		os.RemoveAll(path)
		s := &Scamper{
			OutputPath:       dir,
			Timeout:          1 * time.Second,
			TracelbPTR:       true,
			TracelbWaitProbe: 39,
		}
		s.Binary = test.binary
		s.TraceType = test.traceType
		s.noArgs = test.noArgs
		// Run a traceroute.
		out, err := s.Trace("10.1.1.1", cookie, "", now)
		if test.shouldFail {
			if err == nil {
				t.Error("Trace() = nil, want error")
			}
			continue
		}
		if err != nil {
			t.Errorf("Trace() = %v, want nil", err)
			continue
		}
		got := string(out)
		if strings.TrimSpace(got) != strings.TrimSpace(test.want) {
			t.Errorf("Trace() = %q, want %q", strings.TrimSpace(got), strings.TrimSpace(test.want))
		}
		// Make sure that the output was correctly written to file.
		out, err = ioutil.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		got = string(out)
		if strings.TrimSpace(got) != strings.TrimSpace(test.want) {
			t.Errorf("ReadFile(%v) = %q, want %q", path, got, test.want)
		}
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
		Binary:           "echo",
		OutputPath:       tempdir,
		Timeout:          1 * time.Minute,
		TraceType:        "mda",
		TracelbPTR:       true,
		TracelbWaitProbe: 39,
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

func TestCachedTrace(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "TestCachedTrace")
	rtx.Must(err, "failed to create tempdir")
	defer os.RemoveAll(tempdir)

	// Temporarily set the hostname to a value for testing.
	defer func(oldHn string) {
		hostname = oldHn
	}(hostname)
	hostname = "testhostname"

	s := &Scamper{
		Binary:           "echo",
		OutputPath:       tempdir,
		Timeout:          1 * time.Minute,
		TraceType:        "mda",
		TracelbPTR:       true,
		TracelbWaitProbe: 39,
	}

	faketime := time.Date(2019, time.April, 1, 3, 45, 51, 0, time.UTC)
	prometheusx.GitShortCommit = "Fake Version"
	cachedTrace := []byte(`{"UUID": "ndt-plh7v_1566050090_000000000004D64D"}
	{"type":"cycle-start", "list_name":"/tmp/scamperctrl:51811", "id":1, "hostname":"ndt-plh7v", "start_time":1566691298}
	{"type":"tracelb", "version":"0.1", "userid":0, "method":"icmp-echo", "src":"::ffff:180.87.97.101", "dst":"::ffff:1.47.236.62", "start":{"sec":1566691298, "usec":476221, "ftime":"2019-08-25 00:01:38"}, "probe_size":60, "firsthop":1, "attempts":3, "confidence":95, "tos":0, "gaplimit":3, "wait_timeout":5, "wait_probe":250, "probec":0, "probec_max":3000, "nodec":0, "linkc":0}
	{"type":"cycle-stop", "list_name":"/tmp/scamperctrl:51811", "id":1, "hostname":"ndt-plh7v", "stop_time":1566691298}`)

	_ = s.CachedTrace("ndt-plh7v_1566050090_000000000004D64D", "1", faketime, []byte("Broken cached traceroute"))
	_, errInvalidTest := ioutil.ReadFile(tempdir + "/2019/04/01/20190401T034551Z_" + prefix.UnsafeString() + "_0000000000000001.jsonl")
	if errInvalidTest == nil {
		t.Error("CachedTrace() = nil, want error")
	}

	_ = s.CachedTrace("ndt-plh7v_1566050090_000000000004D64D", "1", faketime, cachedTrace)
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
	if m.CachedTrace != true {
		t.Errorf("got cached result %v, want true", m.CachedTrace)
	}
	wantUUID = "ndt-plh7v_1566050090_000000000004D64D"
	if m.CachedUUID != "ndt-plh7v_1566050090_000000000004D64D" {
		t.Errorf("got cached UUID %q, want %q", m.CachedUUID, wantUUID)
	}

	// Now test an error condition.
	s.OutputPath = "/dev/null"
	if s.CachedTrace("ndt-plh7v_1566050090_000000000004D64D", "1", faketime, cachedTrace) == nil {
		t.Error("CachedTrace() = nil, want error")
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
	wantMeta := []byte("0000000000000ABC\",\"TracerouteCallerVersion\":\"Fake Version\",\"CachedTrace\":true,\"CachedUUID\":\"00EF\"")
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
	if err := s.CachedTrace("", "an invalid cookie", time.Now(), nil); err == nil {
		t.Error("CachedTrace() = nil, want error")
	}
}
