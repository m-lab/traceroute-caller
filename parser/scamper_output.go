// Package parser handles parsing of scamper JSONL.
//
// Refer to scamper source code files scamper/scamper_list.h and
// scamper/tracelb/scamper_tracelb.h for the definitions of cycle_start,
// tracelb, and cycle_stop lines.
package parser

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/m-lab/traceroute-caller/tracer"
)

var (
	errTraceroute     = errors.New("invalid traceroute file")
	errMetadata       = errors.New("invalid metadata")
	errMetadataUUID   = errors.New("invalid UUID (empty)")
	errCycleStart     = errors.New("invalid cycle-start")
	errCycleStartType = errors.New("invalid cycle-start type")
	errTracelb        = errors.New("invalid tracelb")
	errTracelbType    = errors.New("invalid tracelb type")
	errCycleStop      = errors.New("invalid cycle-stop")
	errCycleStopType  = errors.New("invalid cycle-stop type")
)

// TODO: The following structs are almost identical to the structs
//       etl/parser/pt.go and should be defined in one place to be used
//       by both.

// TODO: None of the float64 struct fields in this file are defined
//       as float in scamper source code so it's not clear at all
//       why there are defined float64.  Look into this and change
//       them to the proper unit{8,16,32} types.

// TS contains a unix epoch timestamp.
type TS struct {
	Sec  int64 `json:"sec"`
	Usec int64 `json:"usec"`
}

// Reply describes a single reply message.
type Reply struct {
	Rx       TS      `json:"rx"`
	TTL      int     `json:"ttl"`
	RTT      float64 `json:"rtt"`
	IcmpType int     `json:"icmp_type"`
	IcmpCode int     `json:"icmp_code"`
	IcmpQTos int     `json:"icmp_q_tos"`
	IcmpQTTL int     `json:"icmp_q_ttl"`
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

// ScamperLink describes a single step in the trace.  The probes within a
// ScamperLink appear to have the same value of TTL, but different flow_ids.
type ScamperLink struct {
	Addr   string  `json:"addr"`
	Probes []Probe `json:"probes"`
}

// ScamperNode describes a layer of links.
type ScamperNode struct {
	Addr  string          `json:"addr"`
	Name  string          `json:"name"`
	QTTL  int             `json:"q_ttl"`
	Linkc int64           `json:"linkc"`
	Links [][]ScamperLink `json:"links"`
}

// ScamperOutput encapsulates the four lines of a traceroute:
//   {"UUID":...}
//   {"type":"cycle-start"...}
//   {"type":"tracelb"...}
//   {"type":"cycle-stop"...}
type ScamperOutput struct {
	Metadata   tracer.Metadata
	CycleStart CyclestartLine
	Tracelb    TracelbLine
	CycleStop  CyclestopLine
}

// CyclestartLine contains the information about the scamper "cyclestart"
type CyclestartLine struct {
	Type      string  `json:"type"`
	ListName  string  `json:"list_name"`
	ID        float64 `json:"id"`
	Hostname  string  `json:"hostname"`
	StartTime float64 `json:"start_time"`
}

// TracelbLine contains the actual scamper trace details.
// Not clear why so many fields are floats.  Fields in scamper code are uint16_t and uint8_t
type TracelbLine struct {
	Type        string        `json:"type"`
	Version     string        `json:"version"`
	Userid      float64       `json:"userid"`
	Method      string        `json:"method"`
	Src         string        `json:"src"`
	Dst         string        `json:"dst"`
	Start       TS            `json:"start"`
	ProbeSize   float64       `json:"probe_size"`
	Firsthop    float64       `json:"firsthop"`
	Attempts    float64       `json:"attempts"`
	Confidence  float64       `json:"confidence"`
	Tos         float64       `json:"tos"`
	Gaplint     float64       `json:"gaplint"`
	WaitTimeout float64       `json:"wait_timeout"`
	WaitProbe   float64       `json:"wait_probe"`
	Probec      float64       `json:"probec"`
	ProbecMax   float64       `json:"probec_max"`
	Nodec       float64       `json:"nodec"`
	Linkc       float64       `json:"linkc"`
	Nodes       []ScamperNode `json:"nodes"`
}

// CyclestopLine contains the ending details from the scamper tool.  ID,
// ListName, hostname seem to match CyclestartLine
type CyclestopLine struct {
	Type     string  `json:"type"`
	ListName string  `json:"list_name"`
	ID       float64 `json:"id"`
	Hostname string  `json:"hostname"`
	StopTime float64 `json:"stop_time"`
}

// ParseTraceroute parses scamper output in JSONL format and returns it.
func ParseTraceroute(data []byte) (*ScamperOutput, error) {
	var scamperOutput ScamperOutput
	var err error

	// We account for the last newline because it's a lot faster than
	// stripping it and creating a new slice.  We just validate that
	// the last line is empty.
	lines := bytes.Split(data, []byte("\n"))
	if len(lines) != 5 {
		return nil, errTraceroute
	}
	if len(lines[4]) != 0 {
		return nil, errTraceroute
	}

	// Parse and validate the metadata line.
	if err := json.Unmarshal(lines[0], &scamperOutput.Metadata); err != nil {
		return nil, errMetadata
	}
	if scamperOutput.Metadata.UUID == "" {
		return nil, fmt.Errorf("%w: %v", errMetadataUUID, scamperOutput.Metadata.UUID)
	}

	// Parse and validate the cycle-start line.
	if err := json.Unmarshal(lines[1], &scamperOutput.CycleStart); err != nil {
		return nil, errCycleStart
	}
	if scamperOutput.CycleStart.Type != "cycle-start" {
		return nil, fmt.Errorf("%w: %v", errCycleStartType, scamperOutput.CycleStart.Type)
	}

	// Parse and validate the tracelb line.
	if err = json.Unmarshal(lines[2], &scamperOutput.Tracelb); err != nil {
		return nil, errTracelb
	}
	if scamperOutput.Tracelb.Type != "tracelb" {
		return nil, fmt.Errorf("%w: %v", errTracelbType, scamperOutput.Tracelb.Type)
	}

	// Parse and validate the cycle-stop line.
	if err = json.Unmarshal(lines[3], &scamperOutput.CycleStop); err != nil {
		return nil, errCycleStop
	}
	if scamperOutput.CycleStop.Type != "cycle-stop" {
		return nil, fmt.Errorf("%w: %v", errCycleStopType, scamperOutput.CycleStop.Type)
	}

	return &scamperOutput, nil
}

// ExtractHops parses tracelb and extracts all hop addresses.
func ExtractHops(tracelb *TracelbLine) []string {
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
