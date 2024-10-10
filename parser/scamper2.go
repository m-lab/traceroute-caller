package parser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/m-lab/go/anonymize"
	"github.com/m-lab/traceroute-caller/tracer"
)

var (
	ErrUnsupportedFormat = fmt.Errorf("unsupported marshal format")
)

// ScamperHop describes a layer of hops.
type ScamperHop struct {
	Addr      string  `json:"addr" bigquery:"addr"`
	Name      string  `json:"name" bigquery:"name"`
	ProbeTTL  int32   `json:"probe_ttl" bigquery:"probe_ttl"`
	ProbeID   int32   `json:"probe_id" bigquery:"probe_id"`
	ProbeSize int32   `json:"probe_size" bigquery:"probe_size"`
	Tx        TS      `json:"tx" bigquery:"tx"`
	RTT       float64 `json:"rtt" bigquery:"rtt"`
	ReplyTTL  int32   `json:"reply_ttl" bigquery:"reply_ttl"`
	ReplyTOS  int32   `json:"reply_tos" bigquery:"reply_tos"`
	ReplyIPID int32   `json:"reply_ipid" bigquery:"reply_ipid"`
	ReplySize int32   `json:"reply_size" bigquery:"reply_size"`
	ICMPType  int32   `json:"icmp_type" bigquery:"icmp_type"`
	ICMPCode  int32   `json:"icmp_code" bigquery:"icmp_code"`
	ICMPQTTL  int32   `json:"icmp_q_ttl" bigquery:"icmp_q_ttl"`
	ICMPQIPL  int32   `json:"icmp_q_ipl" bigquery:"icmp_q_ipl"`
	ICMPQTOS  int32   `json:"icmp_q_tos" bigquery:"icmp_q_tos"`
}

// Scamper2 encapsulates the four lines of a traceroute:
//
//	{"UUID":...}
//	{"type":"cycle-start"...}
//	{"type":"trace"...}
//	{"type":"cycle-stop"...}
type Scamper2 struct {
	Metadata   tracer.Metadata
	CycleStart CyclestartLine
	Trace      TraceLine
	CycleStop  CyclestopLine
}

// TraceLine contains scamper regular traceroute details.
type TraceLine struct {
	Type       string       `json:"type" bigquery:"type"`
	Version    string       `json:"version" bigquery:"version"`
	UserID     int32        `json:"userid" bigquery:"userid"`
	Method     string       `json:"method" bigquery:"method"`
	Src        string       `json:"src" bigquery:"src"`
	Dst        string       `json:"dst" bigquery:"dst"`
	ICMPSum    int32        `json:"icmp_sum" bigquery:"icmp_sum"`
	StopReason string       `json:"stop_reason" bigquery:"stop_reason"`
	StopData   int32        `json:"stop_data" bigquery:"stop_data"`
	Start      TS           `json:"start" bigquery:"start"`
	HopCount   int32        `json:"hop_count" bigquery:"hop_count"`
	Attempts   int32        `json:"attempts" bigquery:"attempts"`
	HopLimit   int32        `json:"hoplimit" bigquery:"hoplimit"`
	FirstHop   int32        `json:"firsthop" bigquery:"firsthop"`
	Wait       int32        `json:"wait" bigquery:"wait"`
	WaitProbe  int32        `json:"wait_probe" bigquery:"wait_probe"`
	Tos        int32        `json:"tos" bigquery:"tos"`
	ProbeSize  int32        `json:"probe_size" bigquery:"probe_size"`
	ProbeCount int32        `json:"probe_count" bigquery:"probe_count"`
	Hops       []ScamperHop `json:"hops" bigquery:"hops"`
}

type scamper2Parser struct {
	format string
}

// Format returns the desired output format for this parser.
func (s2 *scamper2Parser) Format() string {
	return s2.format
}

// ParseRawData parses scamper's normal traceroute in JSONL format.
func (s2 *scamper2Parser) ParseRawData(rawData []byte) (ParsedData, error) {
	var scamper2 Scamper2

	// First validate the traceroute data.	We account for the last
	// newline because it's a lot faster than stripping it and creating
	// a new slice.  We just confirm that the last line is empty.
	lines := bytes.Split(rawData, []byte("\n"))
	if len(lines) == 1 || (len(lines) == 2 && len(lines[1]) == 0) {
		err := json.Unmarshal(rawData, &scamper2)
		return &scamper2, err
	}
	if len(lines) != 5 || len(lines[4]) != 0 {
		return nil, ErrTracerouteFile
	}

	// Parse and validate the metadata line.
	if err := json.Unmarshal(lines[0], &scamper2.Metadata); err != nil {
		return nil, ErrMetadata
	}
	if scamper2.Metadata.UUID == "" {
		return nil, fmt.Errorf("%w: %v", ErrMetadataUUID, scamper2.Metadata.UUID)
	}

	// Parse and validate the cycle-start line.
	if err := json.Unmarshal(lines[1], &scamper2.CycleStart); err != nil {
		return nil, ErrCycleStart
	}
	if scamper2.CycleStart.Type != "cycle-start" {
		return nil, fmt.Errorf("%w: %v", ErrCycleStartType, scamper2.CycleStart.Type)
	}

	// Parse and validate the trace line.
	if err := json.Unmarshal(lines[2], &scamper2.Trace); err != nil {
		return nil, ErrTraceLine
	}
	if scamper2.Trace.Type != "trace" {
		return nil, fmt.Errorf("%w: %v", ErrTraceType, scamper2.Trace.Type)
	}

	// Parse and validate the cycle-stop line.
	if err := json.Unmarshal(lines[3], &scamper2.CycleStop); err != nil {
		return nil, ErrCycleStop
	}
	if scamper2.CycleStop.Type != "cycle-stop" {
		return nil, fmt.Errorf("%w: %v", ErrCycleStopType, scamper2.CycleStop.Type)
	}

	return &scamper2, nil
}

// StartTime returns the start time of the traceroute.
func (s2 Scamper2) StartTime() time.Time {
	return time.Unix(int64(s2.CycleStart.StartTime), 0).UTC()
}

// ExtractHops parses the traceroute and extracts all hop addresses.
func (s2 Scamper2) ExtractHops() []string {
	trace := s2.Trace
	// We cannot use net.IP as key because it is a slice.
	hops := make(map[string]struct{}, 100)
	for i := range trace.Hops {
		hop := &trace.Hops[i]
		if net.ParseIP(hop.Addr) != nil {
			hops[hop.Addr] = struct{}{}
		}
	}
	hopStrings := make([]string, 0, len(hops))
	for h := range hops {
		hopStrings = append(hopStrings, h)
	}
	return hopStrings
}

// Anonymize looks for hops that are in the client subnet, and anonymizes them using the given anonymizer.
func (s2 *Scamper2) Anonymize(anon anonymize.IPAnonymizer) {
	trace := s2.Trace
	dst := net.ParseIP(trace.Dst)
	anon.IP(dst)
	s2.Trace.Dst = dst.String()
	for i := range trace.Hops {
		hop := &trace.Hops[i]
		ip := net.ParseIP(hop.Addr)
		if anon.Contains(dst, ip) {
			anon.IP(ip)
			hop.Addr = ip.String()
		}
	}
}

// Marshal encodes the scamper object based on the given format.
func (s2 Scamper2) Marshal(format string) ([]byte, error) {
	switch format {
	case "jsonl":
		return s2.MarshalAsJSONL(), nil
	case "json":
		return s2.MarshalAsJSON()
	}
	return nil, ErrUnsupportedFormat
}

// MarshalAsJSONL encodes the scamper object as JSONL.
func (s2 Scamper2) MarshalAsJSONL() []byte {
	buff := &bytes.Buffer{}
	enc := json.NewEncoder(buff)
	enc.Encode(s2.Metadata)
	enc.Encode(s2.CycleStart)
	enc.Encode(s2.Trace)
	enc.Encode(s2.CycleStop)
	return buff.Bytes()
}

// MarshalAsJSON encodes the scamper object as JSONL.
func (s2 Scamper2) MarshalAsJSON() ([]byte, error) {
	buff := &bytes.Buffer{}
	enc := json.NewEncoder(buff)
	err := enc.Encode(s2)
	return buff.Bytes(), err
}
