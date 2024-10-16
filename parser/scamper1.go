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

// TODO: The following structs are almost identical to the structs
//       etl/parser/pt.go and should be defined in one place to be used
//       by both.

// TODO: None of the float64 struct fields in this file are defined
//       as float in scamper source code so it's not clear at all
//       why there are defined float64.  Look into this and change
//       them to the proper unit{8,16,32} types.

// Reply describes a single reply message.
type Reply struct {
	Rx       TS      `json:"rx" bigquery:"rx"`
	TTL      int     `json:"ttl" bigquery:"ttl"`
	RTT      float64 `json:"rtt" bigquery:"rtt"`
	IcmpType int     `json:"icmp_type" bigquery:"icmp_type"`
	IcmpCode int     `json:"icmp_code" bigquery:"icmp_code"`
	IcmpQTos int     `json:"icmp_q_tos" bigquery:"icmp_q_tos"`
	IcmpQTTL int     `json:"icmp_q_ttl" bigquery:"icmp_q_ttl"`
}

// Probe describes a single probe message, and all the associated replies.
type Probe struct {
	Tx      TS      `json:"tx" bigquery:"tx"`
	Replyc  int     `json:"replyc" bigquery:"replyc"`
	TTL     int64   `json:"ttl" bigquery:"ttl"`
	Attempt int     `json:"attempt" bigquery:"attempt"`
	Flowid  int64   `json:"flowid" bigquery:"flowid"`
	Replies []Reply `json:"replies" bigquery:"replies"` // There is usually just a single reply.
}

// ScamperLink describes a single step in the traceroute.  The probes within a
// ScamperLink appear to have the same value of TTL, but different flow_ids.
type ScamperLink struct {
	Addr   string  `json:"addr" bigquery:"addr"`
	Probes []Probe `json:"probes" bigquery:"probes"`
}

// ScamperNode describes a layer of links.
type ScamperNode struct {
	Addr  string          `json:"addr" bigquery:"addr"`
	Name  string          `json:"name" bigquery:"name"`
	QTTL  int             `json:"q_ttl" bigquery:"q_ttl"`
	Linkc int64           `json:"linkc" bigquery:"linkc"`
	Links [][]ScamperLink `json:"links" bigquery:"-"`
}

// Scamper1 encapsulates the four lines of a traceroute:
//
//	{"UUID":...}
//	{"type":"cycle-start"...}
//	{"type":"tracelb"...}
//	{"type":"cycle-stop"...}
//
// Refer to scamper source code files scamper/scamper_list.h and
// scamper/tracelb/scamper_tracelb.h for the definitions of cycle_start,
// tracelb, and cycle_stop lines.
type Scamper1 struct {
	Metadata   tracer.Metadata
	CycleStart CyclestartLine
	Tracelb    TracelbLine
	CycleStop  CyclestopLine
}

// TracelbLine contains scamper MDA traceroute details.
// Not clear why so many fields are floats.  Fields in scamper code are uint16_t and uint8_t
type TracelbLine struct {
	Type        string        `json:"type" bigquery:"type"`
	Version     string        `json:"version" bigquery:"version"`
	Userid      float64       `json:"userid" bigquery:"userid"`
	Method      string        `json:"method" bigquery:"method"`
	Src         string        `json:"src" bigquery:"src"`
	Dst         string        `json:"dst" bigquery:"dst"`
	Start       TS            `json:"start" bigquery:"start"`
	ProbeSize   float64       `json:"probe_size" bigquery:"probe_size"`
	Firsthop    float64       `json:"firsthop" bigquery:"firsthop"`
	Attempts    float64       `json:"attempts" bigquery:"attempts"`
	Confidence  float64       `json:"confidence" bigquery:"confidence"`
	Tos         float64       `json:"tos" bigquery:"tos"`
	Gaplint     float64       `json:"gaplint" bigquery:"gaplint"`
	WaitTimeout float64       `json:"wait_timeout" bigquery:"wait_timeout"`
	WaitProbe   float64       `json:"wait_probe" bigquery:"wait_probe"`
	Probec      float64       `json:"probec" bigquery:"probec"`
	ProbecMax   float64       `json:"probec_max" bigquery:"probec_max"`
	Nodec       float64       `json:"nodec" bigquery:"nodec"`
	Linkc       float64       `json:"linkc" bigquery:"linkc"`
	Nodes       []ScamperNode `json:"nodes" bigquery:"nodes"`
}

type scamper1Parser struct {
	format string
}

// Format returns the desired output format for this parser.
func (s1 *scamper1Parser) Format() string {
	return s1.format
}

// ParseRawData parses scamper's MDA traceroute in JSONL format.
func (s1 *scamper1Parser) ParseRawData(rawData []byte) (ParsedData, error) {
	var scamper1 Scamper1

	// First validate the traceroute data.	We account for the last
	// newline because it's a lot faster than stripping it and creating
	// a new slice.  We just confirm that the last line is empty.
	lines := bytes.Split(rawData, []byte("\n"))
	if len(lines) != 5 || len(lines[4]) != 0 {
		return nil, ErrTracerouteFile
	}

	// Parse and validate the metadata line.
	if err := json.Unmarshal(lines[0], &scamper1.Metadata); err != nil {
		return nil, ErrMetadata
	}
	if scamper1.Metadata.UUID == "" {
		return nil, fmt.Errorf("%w: %v", ErrMetadataUUID, scamper1.Metadata.UUID)
	}

	// Parse and validate the cycle-start line.
	if err := json.Unmarshal(lines[1], &scamper1.CycleStart); err != nil {
		return nil, ErrCycleStart
	}
	if scamper1.CycleStart.Type != "cycle-start" {
		return nil, fmt.Errorf("%w: %v", ErrCycleStartType, scamper1.CycleStart.Type)
	}

	// Parse and validate the tracelb line.
	if err := json.Unmarshal(lines[2], &scamper1.Tracelb); err != nil {
		return nil, ErrTracelbLine
	}
	if scamper1.Tracelb.Type != "tracelb" {
		return nil, fmt.Errorf("%w: %v", ErrTraceType, scamper1.Tracelb.Type)
	}

	// Parse and validate the cycle-stop line.
	if err := json.Unmarshal(lines[3], &scamper1.CycleStop); err != nil {
		return nil, ErrCycleStop
	}
	if scamper1.CycleStop.Type != "cycle-stop" {
		return nil, fmt.Errorf("%w: %v", ErrCycleStopType, scamper1.CycleStop.Type)
	}

	return &scamper1, nil
}

// StartTime returns the start time of the traceroute.
func (s1 Scamper1) StartTime() time.Time {
	return time.Unix(int64(s1.CycleStart.StartTime), 0).UTC()
}

// ExtractHops parses tracelb and extracts all hop addresses.
func (s1 Scamper1) ExtractHops() []string {
	tracelb := s1.Tracelb
	// We cannot use net.IP as key because it is a slice.
	hops := make(map[string]struct{}, 100)
	for i := range tracelb.Nodes {
		node := &tracelb.Nodes[i]
		if net.ParseIP(node.Addr) != nil {
			hops[node.Addr] = struct{}{}
		}
		for j := range node.Links {
			links := node.Links[j]
			for k := range links {
				link := &links[k]
				if net.ParseIP(link.Addr) != nil {
					hops[link.Addr] = struct{}{}
				}
			}
		}
	}
	hopStrings := make([]string, 0, len(hops))
	for h := range hops {
		hopStrings = append(hopStrings, h)
	}
	return hopStrings
}

// Anonymize looks for hops that are in the client subnet, and anonymizes them using the given anonymizer.
func (s1 *Scamper1) Anonymize(anon anonymize.IPAnonymizer) {
	tracelb := s1.Tracelb
	dst := net.ParseIP(tracelb.Dst)
	anon.IP(dst)
	s1.Tracelb.Dst = dst.String()

	for i := range tracelb.Nodes {
		node := &tracelb.Nodes[i]
		ip := net.ParseIP(node.Addr)
		if anon.Contains(dst, ip) {
			anon.IP(ip)
			node.Addr = ip.String()
		}
		for j := range node.Links {
			links := node.Links[j]
			for k := range links {
				link := &links[k]
				ip = net.ParseIP(link.Addr)
				if anon.Contains(dst, ip) {
					anon.IP(ip)
					link.Addr = ip.String()
				}
			}
		}
	}
}

// Marshal encodes the scamper object based on the given format.
func (s1 *Scamper1) Marshal(format string) ([]byte, error) {
	switch format {
	case "jsonl":
		return s1.MarshalAsJSONL(), nil
	case "json":
		// TODO(soltesz): translate the Scamper1 struct into a format that can be imported into BigQuery.
	}
	return nil, ErrUnsupportedFormat
}

// MarshalAsJSONL encodes the scamper object as JSONL.
func (s1 *Scamper1) MarshalAsJSONL() []byte {
	buff := &bytes.Buffer{}
	enc := json.NewEncoder(buff)
	enc.Encode(s1.Metadata)
	enc.Encode(s1.CycleStart)
	enc.Encode(s1.Tracelb)
	enc.Encode(s1.CycleStop)
	return buff.Bytes()
}
