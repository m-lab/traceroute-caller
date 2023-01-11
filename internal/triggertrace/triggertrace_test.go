package triggertrace

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/m-lab/go/anonymize"
	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/traceroute-caller/hopannotation"
	"github.com/m-lab/traceroute-caller/internal/ipcache"
	"github.com/m-lab/traceroute-caller/parser"
	"github.com/m-lab/traceroute-caller/tracer"
	"github.com/m-lab/uuid-annotator/annotator"
)

var (
	forceTracerouteErr = "99.99.99.99" // force a failure running a traceroute
	forceParseErr      = "88.88.88.88" // force a failure parsing a traceroute output
	forceExtractErr    = "77.77.77.77" // force a failure extracting hops
	forceAnnotateErr   = "66.66.66.66" // force a failure annotating hops
	forceWriteErr      = "write-err-8" // force a failure writing trace
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

type fakeTracer struct {
	nTraces       int32
	nCachedTraces int32
}

func (ft *fakeTracer) Trace(remoteIP, uuid string, t time.Time) ([]byte, error) {
	defer func() { atomic.AddInt32(&ft.nTraces, 1) }()
	var jsonl string
	switch remoteIP {
	case forceTracerouteErr:
		return nil, errors.New("forced traceroute error")
	case forceParseErr:
		return []byte("forced parse error"), nil
	case forceExtractErr:
		jsonl = "./testdata/extract-error.jsonl"
	case forceAnnotateErr:
		jsonl = "./testdata/annotate-error.jsonl"
	default:
		jsonl = "./testdata/valid.jsonl"
	}
	content, err := os.ReadFile(jsonl)
	if err != nil {
		return nil, err
	}
	return content, nil
}

func (ft *fakeTracer) WriteFile(uuid string, t time.Time, data []byte) error {
	switch uuid {
	case forceWriteErr:
		return errors.New("forced write error")
	default:
		return nil
	}
}

func (ft *fakeTracer) CachedTrace(uuid string, t time.Time, cachedTest []byte) ([]byte, error) {
	defer func() { atomic.AddInt32(&ft.nCachedTraces, 1) }()
	fmt.Printf("\nCachedTrace()\n")
	return nil, nil
}

func (ft *fakeTracer) DontTrace() {
	log.Fatal("should not have called DontTrace()")
}

func (ft *fakeTracer) Traces() int32 {
	return atomic.LoadInt32(&ft.nTraces)
}

func (ft *fakeTracer) TracesCached() int32 {
	return atomic.LoadInt32(&ft.nCachedTraces)
}

type fakeAnnotator struct {
	nAnnotates int32
}

func (fa *fakeAnnotator) Annotate(ctx context.Context, ips []string) (map[string]*annotator.ClientAnnotations, error) {
	defer func() { atomic.AddInt32(&fa.nAnnotates, 1) }()
	annotations := make(map[string]*annotator.ClientAnnotations)
	for _, ip := range ips {
		if ip == forceAnnotateErr {
			return nil, errors.New("forced annotate error")
		}
		annotations[ip] = nil
	}
	return annotations, nil
}

func TestNewHandler(t *testing.T) {
	saveNetInterfaceAddrs := netInterfaceAddrs
	defer func() { netInterfaceAddrs = saveNetInterfaceAddrs }()

	netInterfaceAddrs = fakeInterfaceAddrsBad
	if _, err := newHandler(t, &fakeTracer{}); err == nil {
		t.Fatalf("NewHandler() = nil, want error")
	}

	netInterfaceAddrs = fakeInterfaceAddrs
	if _, err := newHandler(t, &fakeTracer{}); err != nil {
		t.Fatalf("NewHandler() = %v, want nil", err)
	}
}

func TestOpen(t *testing.T) {
	saveNetInterfaceAddrs := netInterfaceAddrs
	netInterfaceAddrs = fakeInterfaceAddrs
	defer func() { netInterfaceAddrs = saveNetInterfaceAddrs }()

	handler, err := newHandler(t, &fakeTracer{})
	if err != nil {
		t.Fatalf("NewHandler() = %v, want nil", err)
	}

	tests := []struct {
		name   string
		uuid   string
		sockID *inetdiag.SockID
	}{
		{"bad1", "", &inetdiag.SockID{SrcIP: "127.0.0.1", DstIP: "1.2.3.4"}}, // empty uuid
		{"bad1", "00001", nil},                                                     // nil sockID
		{"bad1", "00002", &inetdiag.SockID{SrcIP: "0.0.0.0"}},                      // DstIP empty
		{"bad1", "00003", &inetdiag.SockID{SrcIP: "invalid IP"}},                   // SrcIP invalid
		{"bad1", "00004", &inetdiag.SockID{SrcIP: "1.2.3.4", DstIP: "4.3.2.1"}},    // no local IP
		{"good1", "00005", &inetdiag.SockID{SrcIP: "127.0.0.1", DstIP: "1.2.3.4"}}, // SrcIP local
		{"good2", "00006", &inetdiag.SockID{SrcIP: "1.2.3.4", DstIP: "127.0.0.1"}}, // DstIP local
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			handler.Open(context.TODO(), time.Now(), test.uuid, test.sockID)
		})
	}
}

func TestClose(t *testing.T) {
	saveNetInterfaceAddrs := netInterfaceAddrs
	netInterfaceAddrs = fakeInterfaceAddrs
	defer func() { netInterfaceAddrs = saveNetInterfaceAddrs }()

	tests := []struct {
		name              string
		srcIP             string
		dstIP             string
		uuid              string
		callOpen          bool
		shouldWait        bool
		wantNTraces       int32
		wantNTracesCached int32
	}{
		{"bad1", "127.0.0.1", "1.2.3.4", "", true, false, 0, 0},
		{"bad2", "127.0.0.1", "2.3.4.5", "00001", false, false, 0, 0},
		{"bad3", "127.0.0.1", forceTracerouteErr, "00002", true, true, 1, 0},
		{"bad4", "127.0.0.1", forceParseErr, "00003", true, true, 1, 0},
		{"bad5", "127.0.0.1", forceExtractErr, "00004", true, true, 1, 0},
		{"bad6", "127.0.0.1", forceAnnotateErr, "00005", true, true, 1, 0},
		{"good1", "127.0.0.1", "3.4.5.6", "00006", true, true, 1, 0},
		{"good2", "4.5.6.7", "127.0.0.1", "00007", true, true, 1, 1},
		{"bad7", "127.0.0.1", "192.168.33.2", forceWriteErr, true, true, 1, 0},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			tracer := &fakeTracer{}
			handler, err := newHandler(t, tracer)
			if err != nil {
				t.Fatalf("NewHandler() = %v, want nil", err)
			}
			if test.shouldWait {
				handler.done = make(chan struct{})
			}
			sockID := &inetdiag.SockID{SrcIP: test.srcIP, DstIP: test.dstIP}
			if test.callOpen {
				handler.Open(context.TODO(), time.Now(), test.uuid, sockID)
			}
			handler.Close(context.TODO(), time.Now(), test.uuid)
			if test.shouldWait {
				waitForTrace(t, handler)
			}
			if n := tracer.Traces(); n != test.wantNTraces {
				t.Fatalf("tracer.Traces() = %d, want %d", n, test.wantNTraces)
			}
			if n := tracer.TracesCached(); n != 0 {
				t.Fatalf("tracer.TracesCached() = %d, want 0", n)
			}
			// Should we do this again to make sure that the traceroute
			// is served from the cache?
			if test.wantNTracesCached > 0 {
				handler.done = make(chan struct{})
				handler.Open(context.TODO(), time.Now(), test.uuid, sockID)
				handler.Close(context.TODO(), time.Now(), test.uuid)
				waitForTrace(t, handler)
				if n := tracer.TracesCached(); n != test.wantNTracesCached {
					t.Fatalf("tracer.TracesCached() = %d, want %d", n, test.wantNTracesCached)
				}
			}
		})
	}
}

func newHandler(t *testing.T, tracer TracerWriter) (*Handler, error) {
	ipcCfg := ipcache.Config{
		EntryTimeout: 2 * time.Second,
		ScanPeriod:   1 * time.Second,
	}
	annotator := &fakeAnnotator{}
	haCfg := hopannotation.Config{
		AnnotatorClient: annotator,
		OutputPath:      path.Join(t.TempDir(), "annotation1"),
	}
	newParser, err := parser.New("mda")
	if err != nil {
		return nil, err
	}
	return NewHandler(context.TODO(), tracer, ipcCfg, newParser, haCfg)
}

func waitForTrace(t *testing.T, handler *Handler) {
	t.Helper()
	select {
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for test to complete")
	case <-handler.done:
		handler.done = nil
	}
}

func fakeInterfaceAddrs() ([]net.Addr, error) {
	_, nw, _ := net.ParseCIDR("127.0.0.1/32")
	ip4, _ := net.ResolveIPAddr("ip4", "11.22.33.44")
	ip6, _ := net.ResolveIPAddr("ip6", "::1")
	return []net.Addr{
		nw,
		ip4,
		ip6,
	}, nil
}

func fakeInterfaceAddrsBad() ([]net.Addr, error) {
	return nil, errors.New("forced inet.InterfaceAddrs error")
}

var (
	staticIPv4None = &parser.Scamper1{
		Metadata:   tracer.Metadata{UUID: "ndt-b9w8b_1667420871_00000000001EDE79"},
		CycleStart: parser.CyclestartLine{Type: "cycle-start", ListName: "default", ID: 0, Hostname: "ndt-b9w8b", StartTime: 1.671301854e+09},
		CycleStop:  parser.CyclestopLine{Type: "cycle-stop", ListName: "default", ID: 0, Hostname: "ndt-b9w8b", StopTime: 1.671301856e+09},
		Tracelb: parser.TracelbLine{
			Type:    "tracelb",
			Version: "0.1",
			Method:  "icmp-echo",
			Src:     "1.1.1.1",
			Dst:     "4.4.4.4",
			Nodes: []parser.ScamperNode{
				{
					Addr:  "2.2.2.2",
					Links: [][]parser.ScamperLink{{{Addr: "3.3.3.3"}}},
				},
				{
					Addr:  "3.3.3.3",
					Links: [][]parser.ScamperLink{{{Addr: "4.4.4.2"}}},
				},
				{
					Addr:  "4.4.4.2",
					Links: [][]parser.ScamperLink{{{Addr: "4.4.4.4"}}},
				},
			},
		},
	}

	staticIPv4Netblock = &parser.Scamper1{
		Metadata:   tracer.Metadata{UUID: "ndt-b9w8b_1667420871_00000000001EDE79"},
		CycleStart: parser.CyclestartLine{Type: "cycle-start", ListName: "default", ID: 0, Hostname: "ndt-b9w8b", StartTime: 1.671301854e+09},
		CycleStop:  parser.CyclestopLine{Type: "cycle-stop", ListName: "default", ID: 0, Hostname: "ndt-b9w8b", StopTime: 1.671301856e+09},
		Tracelb: parser.TracelbLine{
			Type:    "tracelb",
			Version: "0.1",
			Method:  "icmp-echo",
			Src:     "1.1.1.1",
			Dst:     "4.4.4.0", // NETBLOCK
			Nodes: []parser.ScamperNode{
				{
					Addr:  "2.2.2.2",
					Links: [][]parser.ScamperLink{{{Addr: "3.3.3.3"}}},
				},
				{
					Addr:  "3.3.3.3",
					Links: [][]parser.ScamperLink{{{Addr: "4.4.4.0"}}}, // NETBLOCK
				},
				{
					Addr:  "4.4.4.0",                                   // NETBLOCK
					Links: [][]parser.ScamperLink{{{Addr: "4.4.4.0"}}}, // NETBLOCK
				},
			},
		},
	}

	staticIPv6None = &parser.Scamper1{
		Metadata:   tracer.Metadata{UUID: "ndt-b9w8b_1667420871_00000000001EDE79"},
		CycleStart: parser.CyclestartLine{Type: "cycle-start", ListName: "default", ID: 0, Hostname: "ndt-b9w8b", StartTime: 1.671301854e+09},
		CycleStop:  parser.CyclestopLine{Type: "cycle-stop", ListName: "default", ID: 0, Hostname: "ndt-b9w8b", StopTime: 1.671301856e+09},
		Tracelb: parser.TracelbLine{
			Type:    "tracelb",
			Version: "0.1",
			Method:  "icmp-echo",
			Src:     "2001:1:1:1::1",
			Dst:     "2006:4:4:4::4",
			Nodes: []parser.ScamperNode{
				{
					Addr:  "2001:2:2:2::2",
					Links: [][]parser.ScamperLink{{{Addr: "2001:3:3:3::3"}}},
				},
				{
					Addr:  "2001:3:3:3::3",
					Links: [][]parser.ScamperLink{{{Addr: "2006:4:4:4::2"}}},
				},
				{
					Addr:  "2006:4:4:4::2",
					Links: [][]parser.ScamperLink{{{Addr: "2006:4:4:4::4"}}},
				},
			},
		},
	}

	staticIPv6Netblock = &parser.Scamper1{
		Metadata:   tracer.Metadata{UUID: "ndt-b9w8b_1667420871_00000000001EDE79"},
		CycleStart: parser.CyclestartLine{Type: "cycle-start", ListName: "default", ID: 0, Hostname: "ndt-b9w8b", StartTime: 1.671301854e+09},
		CycleStop:  parser.CyclestopLine{Type: "cycle-stop", ListName: "default", ID: 0, Hostname: "ndt-b9w8b", StopTime: 1.671301856e+09},
		Tracelb: parser.TracelbLine{
			Type:    "tracelb",
			Version: "0.1",
			Method:  "icmp-echo",
			Src:     "2001:1:1:1::1",
			Dst:     "2006:4:4:4::", // NETBLOCK
			Nodes: []parser.ScamperNode{
				{
					Addr:  "2001:2:2:2::2",
					Links: [][]parser.ScamperLink{{{Addr: "2001:3:3:3::3"}}},
				},
				{
					Addr:  "2001:3:3:3::3",
					Links: [][]parser.ScamperLink{{{Addr: "2006:4:4:4::"}}}, // NETBLOCK
				},
				{
					Addr:  "2006:4:4:4::",                                   // NETBLOCK
					Links: [][]parser.ScamperLink{{{Addr: "2006:4:4:4::"}}}, // NETBLOCK
				},
			},
		},
	}
)

type staticTracer struct {
	fakeTracer
	input  *parser.Scamper1
	output *parser.Scamper1
}

func (st *staticTracer) Trace(remoteIP, uuid string, t time.Time) ([]byte, error) {
	defer func() { atomic.AddInt32(&st.nTraces, 1) }()
	return st.input.MarshalJSONL(), nil
}

func (st *staticTracer) WriteFile(uuid string, t time.Time, data []byte) error {
	p, err := parser.New("mda")
	if err != nil {
		return err
	}
	pd, err := p.ParseRawData(data)
	st.output = pd.(*parser.Scamper1)
	if err != nil {
		return err
	}
	return nil
}

func TestAnonymize(t *testing.T) {

	tests := []struct {
		name   string
		srcIP  string
		dstIP  string
		uuid   string
		method anonymize.Method
		input  *parser.Scamper1
		want   *parser.Scamper1
	}{
		{"ipv4-netblock-none", "1.1.1.1", "4.4.4.4", "v4-none", anonymize.None, staticIPv4None, staticIPv4None},
		{"ipv4-netblock-netblock", "1.1.1.1", "4.4.4.4", "v4-netblock", anonymize.Netblock, staticIPv4None, staticIPv4Netblock},
		{"ipv6-netblock-none", "2001:1:1:1::1", "2006:4:4:4::4", "v6-none", anonymize.None, staticIPv6None, staticIPv6None},
		{"ipv6-netblock-netblock", "2001:1:1:1::1", "2006:4:4:4::4", "v6-netblock", anonymize.Netblock, staticIPv6None, staticIPv6Netblock},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			anonymize.IPAnonymizationFlag = tt.method
			st := &staticTracer{
				input: tt.input,
			}
			h, err := newHandler(t, st)
			if err != nil {
				t.Fatalf("NewHandler() = %v, want nil", err)
			}
			l := net.ParseIP(tt.srcIP)
			h.LocalIPs = []*net.IP{&l}
			h.done = make(chan struct{})
			sockID := &inetdiag.SockID{SrcIP: tt.srcIP, DstIP: tt.dstIP}
			h.Open(context.TODO(), time.Now(), tt.uuid, sockID)
			h.Close(context.TODO(), time.Now(), tt.uuid)
			waitForTrace(t, h)

			if diff := deep.Equal(st.output, tt.want); diff != nil {
				t.Errorf("Close() anonymize failed; got != want\n%s", strings.Join(diff, "\n"))
			}
		})
	}

}
