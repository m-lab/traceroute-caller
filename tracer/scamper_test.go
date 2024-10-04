package tracer

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/m-lab/go/prometheusx"
	"github.com/m-lab/go/rtx"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func TestNewScamper(t *testing.T) {
	nonWritableDir := "testdata/non-writable"
	if err := os.MkdirAll(nonWritableDir, 0555); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(nonWritableDir)
	tests := []struct {
		binary           string
		outputPath       string
		timeout          time.Duration
		traceType        string
		tracelbWaitProbe int
		shouldFail       bool
		want             string
	}{
		{"testdata", "testdata", 900 * time.Second, "mda", 15, true, "is not an executable file"},
		{"testdata/non-existent", "testdata", 900 * time.Second, "mda", 15, true, "is not an executable file"},
		{"testdata/non-executable", "testdata", 900 * time.Second, "mda", 15, true, "is not an executable file"},
		{"/bin/echo", "/dev/null", 900 * time.Second, "mda", 15, true, "failed to create directory"},
		{"/bin/echo", nonWritableDir, 900 * time.Second, "mda", 15, true, "failed to create a directory inside"},
		{"/bin/echo", "testdata", 0, "mda", 15, true, "invalid timeout value (min: 1s, max 3600s)"},
		{"/bin/echo", "testdata", 3601 * time.Second, "mda", 15, true, "invalid timeout value (min: 1s, max 3600s)"},
		{"/bin/echo", "testdata", 900 * time.Second, "bad", 15, true, "invalid traceroute type"},
		{"/bin/echo", "testdata", 900 * time.Second, "mda", 14, true, "invalid tracelb wait probe value"},
		{"/bin/echo", "testdata", 900 * time.Second, "mda", 201, true, "invalid tracelb wait probe value"},
		{"/bin/echo", "testdata", 900 * time.Second, "mda", 25, false, ""},
		{"/bin/echo", "testdata", 900 * time.Second, "regular", 25, false, ""},
	}
	for _, test := range tests {
		scamperCfg := ScamperConfig{
			Binary:           test.binary,
			OutputPath:       test.outputPath,
			Timeout:          test.timeout,
			TraceType:        test.traceType,
			TracelbWaitProbe: test.tracelbWaitProbe,
		}
		_, err := NewScamper(scamperCfg)
		if err != nil {
			if !test.shouldFail || !strings.Contains(err.Error(), test.want) {
				t.Errorf("Validate() = %v, want %q", err, test.want)
			}
		} else if test.shouldFail {
			t.Errorf("Validate() = nil, want %s", test.want)
		}
	}
}

func TestEmptyUUID(t *testing.T) {
	wantErr := "uuid is empty"
	scamperCfg := ScamperConfig{
		Binary:           "/bin/false",
		OutputPath:       t.TempDir(),
		Timeout:          1 * time.Second,
		TraceType:        "mda",
		TracelbWaitProbe: 39,
		TracelbPTR:       false,
	}
	s, err := NewScamper(scamperCfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Trace("1.2.3.4", "", time.Now())
	if err == nil || !strings.Contains(err.Error(), wantErr) {
		t.Errorf("Trace() = %v, want %q", err, wantErr)
	}
	_, err = s.CachedTrace("", time.Now(), []byte("does not matter"))
	if err == nil || !strings.Contains(err.Error(), wantErr) {
		t.Errorf("Trace() = %v, want %q", err, wantErr)
	}
}

func TestTrace(t *testing.T) {
	tempdir := t.TempDir()
	yyyymmdd := "/2003/11/09/20031109T155559Z"
	uuid := "12AB"
	filename := tempdir + yyyymmdd + "_" + uuid + ".jsonl"
	now := time.Date(2003, 11, 9, 15, 55, 59, 0, time.UTC)
	tests := []struct {
		binary     string
		traceType  string
		tracelbPTR bool
		shouldFail bool
		want       string
	}{
		{"testdata/fail", "mda", true, true, "exit status 1"},
		{"testdata/loop", "mda", true, true, "signal: killed"},

		{"/bin/echo", "mda", true, false, `{"UUID":"` + uuid + `","TracerouteCallerVersion":"` + prometheusx.GitShortCommit + `","CachedResult":false,"CachedUUID":""}
-o- -O json -I tracelb -P icmp-echo -q 3 -W 39 -O ptr 10.1.1.1`},
		{"/bin/echo", "mda", false, false, `{"UUID":"` + uuid + `","TracerouteCallerVersion":"` + prometheusx.GitShortCommit + `","CachedResult":false,"CachedUUID":""}
-o- -O json -I tracelb -P icmp-echo -q 3 -W 39 10.1.1.1`},
	}
	for _, test := range tests {
		os.RemoveAll(filename)
		scamperCfg := ScamperConfig{
			Binary:           test.binary,
			OutputPath:       tempdir,
			Timeout:          1 * time.Second,
			TraceType:        test.traceType,
			TracelbWaitProbe: 39,
			TracelbPTR:       test.tracelbPTR,
		}
		s, err := NewScamper(scamperCfg)
		if err != nil {
			t.Fatal(err)
		}
		// Run a traceroute.
		out, err := s.Trace("10.1.1.1", uuid, now)
		if test.shouldFail {
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Errorf("Trace() = %q, want %q", err, test.want)
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
		err = s.WriteFile(uuid, now, out)
		if err != nil {
			t.Errorf("WriteFile() = %v, want nil", err)
			continue
		}
		// Make sure that the output was correctly written to file.
		out, err = os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		got = string(out)
		if strings.TrimSpace(got) != strings.TrimSpace(test.want) {
			t.Errorf("ReadFile(%v) = %q, want %q", filename, got, test.want)
		}
	}
}

func TestTraceWritesMeta(t *testing.T) {
	tempdir := t.TempDir()

	// Temporarily set the hostname to a value for testing.
	defer func(oldHn string) {
		hostname = oldHn
	}(hostname)
	hostname = "testhostname"

	scamperCfg := ScamperConfig{
		Binary:           "/bin/echo",
		OutputPath:       tempdir,
		Timeout:          1 * time.Minute,
		TraceType:        "mda",
		TracelbPTR:       true,
		TracelbWaitProbe: 39,
	}
	s, err := NewScamper(scamperCfg)
	if err != nil {
		t.Fatal(err)
	}
	faketime := time.Date(2019, time.April, 1, 3, 45, 51, 0, time.UTC)
	prometheusx.GitShortCommit = "Fake Version"
	wantUUID := "0123456789"
	out, err := s.Trace("1.2.3.4", wantUUID, faketime)
	if err != nil {
		t.Errorf("Trace() = %v, want nil", err)
	}
	err = s.WriteFile(wantUUID, faketime, out)
	if err != nil {
		t.Errorf("WriteFile() = %v, want nil", err)
	}

	// Unmarshal the first line of the output file.
	out, err = os.ReadFile(tempdir + "/2019/04/01/20190401T034551Z_" + wantUUID + ".jsonl")
	rtx.Must(err, "failed to read file")
	m := Metadata{}
	lines := strings.Split(string(out), "\n")
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
	tempdir := t.TempDir()

	// Temporarily set the hostname to a value for testing.
	defer func(oldHn string) {
		hostname = oldHn
	}(hostname)
	hostname = "testhostname"

	scamperCfg := ScamperConfig{
		Binary:           "/bin/echo",
		OutputPath:       tempdir,
		Timeout:          1 * time.Minute,
		TraceType:        "mda",
		TracelbPTR:       true,
		TracelbWaitProbe: 39,
	}
	s, err := NewScamper(scamperCfg)
	if err != nil {
		t.Fatal(err)
	}

	faketime := time.Date(2019, time.April, 1, 3, 45, 51, 0, time.UTC)
	prometheusx.GitShortCommit = "Fake Version"
	uuid := "ndt-plh7v_1566050090_000000000004D64D"
	cachedTrace := []byte(`{"UUID": "ndt-plh7v_1566050090_000000000004D64D"}
	{"type":"cycle-start", "list_name":"/tmp/scamperctrl:51811", "id":1, "hostname":"ndt-plh7v", "start_time":1566691298}
	{"type":"tracelb", "version":"0.1", "userid":0, "method":"icmp-echo", "src":"::ffff:180.87.97.101", "dst":"::ffff:1.47.236.62", "start":{"sec":1566691298, "usec":476221, "ftime":"2019-08-25 00:01:38"}, "probe_size":60, "firsthop":1, "attempts":3, "confidence":95, "tos":0, "gaplimit":3, "wait_timeout":5, "wait_probe":250, "probec":0, "probec_max":3000, "nodec":0, "linkc":0}
	{"type":"cycle-stop", "list_name":"/tmp/scamperctrl:51811", "id":1, "hostname":"ndt-plh7v", "stop_time":1566691298}`)

	_, err = s.CachedTrace(uuid, faketime, []byte("Broken cached traceroute"))
	if err == nil {
		t.Error("CacheTrace() returned nil error, want error")
	}

	b, err := s.CachedTrace(uuid, faketime, cachedTrace)
	if err != nil {
		t.Errorf("CacheTrace() = %v, want nil", err)
	}
	// Unmarshal the first line of the output file.
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
	if m.CachedUUID != uuid {
		t.Errorf("got cached UUID %q, want %q", m.CachedUUID, uuid)
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
	scamperCfg := ScamperConfig{
		Binary:           "/bin/echo",
		OutputPath:       "/tmp",
		Timeout:          1 * time.Minute,
		TraceType:        "mda",
		TracelbPTR:       true,
		TracelbWaitProbe: 39,
	}
	s, err := NewScamper(scamperCfg)
	if err != nil {
		t.Fatal(err)
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

func TestGenerateFilename(t *testing.T) {
	_, err := generateFilename("/var/empty", "0000", "jsonl", time.Now())
	wantErrStr := "failed to create output directory"
	if err == nil || !strings.Contains(err.Error(), wantErrStr) {
		t.Errorf("generateFilename() = %v, want %v", err, wantErrStr)
	}
}
