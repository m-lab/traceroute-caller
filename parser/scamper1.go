package parser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"time"

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
	Rx       TS      `json:"rx"`
	TTL      int     `json:"ttl"`
	RTT      float64 `json:"rtt"`
	IcmpType int     `json:"icmp_type" bigquery:"icmp_type"`
	IcmpCode int     `json:"icmp_code" bigquery:"icmp_code"`
	IcmpQTos int     `json:"icmp_q_tos" bigquery:"icmp_q_tos"`
	IcmpQTTL int     `json:"icmp_q_ttl" bigquery:"icmp_q_ttl"`
}

// Probe describes a single probe message, and all the associated replies.
type Probe struct {
	Tx      TS      `json:"tx"`
	Replyc  int     `json:"replyc"`
	TTL     int64   `json:"ttl"`
	Attempt int     `json:"attempt"`
	Flowid  int64   `json:"flowid"`
	Replies []Reply `json:"replies"` // There is usually just a single reply
}

// ScamperLink describes a single step in the traceroute.  The probes within a
// ScamperLink appear to have the same value of TTL, but different flow_ids.
type ScamperLink struct {
	Addr   string  `json:"addr"`
	Probes []Probe `json:"probes"`
}

// ScamperNode describes a layer of links.
type ScamperNode struct {
	Addr  string          `json:"addr"`
	Name  string          `json:"name"`
	QTTL  int             `json:"q_ttl" bigquery:"q_ttl"`
	Linkc int64           `json:"linkc"`
	Links [][]ScamperLink `json:"links"`
}

// Scamper1 encapsulates the four lines of a traceroute:
//   {"UUID":...}
//   {"type":"cycle-start"...}
//   {"type":"tracelb"...}
//   {"type":"cycle-stop"...}
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
	Type        string        `json:"type"`
	Version     string        `json:"version"`
	Userid      float64       `json:"userid"`
	Method      string        `json:"method"`
	Src         string        `json:"src"`
	Dst         string        `json:"dst"`
	Start       TS            `json:"start"`
	ProbeSize   float64       `json:"probe_size" bigquery:"probe_size"`
	Firsthop    float64       `json:"firsthop"`
	Attempts    float64       `json:"attempts"`
	Confidence  float64       `json:"confidence"`
	Tos         float64       `json:"tos"`
	Gaplint     float64       `json:"gaplint"`
	WaitTimeout float64       `json:"wait_timeout" bigquery:"wait_timeout"`
	WaitProbe   float64       `json:"wait_probe" bigquery:"wait_probe"`
	Probec      float64       `json:"probec"`
	ProbecMax   float64       `json:"probec_max" bigquery:"probec_max"`
	Nodec       float64       `json:"nodec"`
	Linkc       float64       `json:"linkc"`
	Nodes       []ScamperNode `json:"nodes"`
}

type scamper1Parser struct {
}

// ParseRawData parses scamper's MDA traceroute in JSONL format.
func (s1 *scamper1Parser) ParseRawData(rawData []byte) (ParsedData, error) {
	var scamper1 Scamper1
	var err error

	// First validate the traceroute data.	We account for the last
	// newline because it's a lot faster than stripping it and creating
	// a new slice.  We just confirm that the last line is empty.
	lines := bytes.Split(rawData, []byte("\n"))
	if len(lines) != 5 || len(lines[4]) != 0 {
		return nil, errTracerouteFile
	}

	// Parse and validate the metadata line.
	if err := json.Unmarshal(lines[0], &scamper1.Metadata); err != nil {
		return nil, errMetadata
	}
	if scamper1.Metadata.UUID == "" {
		return nil, fmt.Errorf("%w: %v", errMetadataUUID, scamper1.Metadata.UUID)
	}

	// Parse and validate the cycle-start line.
	if err := json.Unmarshal(lines[1], &scamper1.CycleStart); err != nil {
		return nil, errCycleStart
	}
	if scamper1.CycleStart.Type != "cycle-start" {
		return nil, fmt.Errorf("%w: %v", errCycleStartType, scamper1.CycleStart.Type)
	}

	// Parse and validate the tracelb line.
	if err = json.Unmarshal(lines[2], &scamper1.Tracelb); err != nil {
		return nil, errTracelbLine
	}
	if scamper1.Tracelb.Type != "tracelb" {
		return nil, fmt.Errorf("%w: %v", errTraceType, scamper1.Tracelb.Type)
	}

	// Parse and validate the cycle-stop line.
	if err = json.Unmarshal(lines[3], &scamper1.CycleStop); err != nil {
		return nil, errCycleStop
	}
	if scamper1.CycleStop.Type != "cycle-stop" {
		return nil, fmt.Errorf("%w: %v", errCycleStopType, scamper1.CycleStop.Type)
	}

	return scamper1, nil
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
		hops[node.Addr] = struct{}{}
		for j := range node.Links {
			links := node.Links[j]
			for k := range links {
				link := &links[k]
				// Parse the IP string, to avoid formatting variations.
				ip := net.ParseIP(link.Addr)
				if ip.String() != "<nil>" {
					hops[ip.String()] = struct{}{}
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
