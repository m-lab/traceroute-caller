// Package parser handles parsing of scamper JSONL.
//
// Refer to scamper source code files scamper/scamper_list.h and
// scamper/tracelb/scamper_tracelb.h for the definitions of cycle_start,
// tracelb, and cycle_stop lines.
package parser

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

var (
	errNumLines       = errors.New("test has wrong number of lines")
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

// There are 4 lines in the traceroute test .jsonl file.
// The first line is defined in Metadata
// The next three lines are the standard scamper JSONL output containing:
//   cyclestartLine
//   TracelbLine
//   cyclestopLine

// cyclestartLine contains the information about the scamper "cyclestart"
type cyclestartLine struct {
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

// cyclestopLine contains the ending details from the scamper tool.  ID,
// ListName, hostname seem to match cyclestartLine
type cyclestopLine struct {
	Type     string  `json:"type"`
	ListName string  `json:"list_name"`
	ID       float64 `json:"id"`
	Hostname string  `json:"hostname"`
	StopTime float64 `json:"stop_time"`
}

// ExtractStartTime extracts the "start_time" field of the "cycle-start"
// line from scamper JSONL output.
func ExtractStartTime(data []byte) (time.Time, error) {
	var cycleStart cyclestartLine
	var epoch int64

	jsonStrings := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(jsonStrings) != 4 {
		return time.Unix(epoch, 0), errNumLines
	}

	// Validate the cycle-start line.
	err := json.Unmarshal([]byte(jsonStrings[1]), &cycleStart)
	if err != nil {
		return time.Unix(epoch, 0), errCycleStart
	}
	if cycleStart.Type != "cycle-start" {
		return time.Unix(epoch, 0), fmt.Errorf("%w: %v", errCycleStartType, cycleStart.Type)
	}
	return time.Unix(int64(cycleStart.StartTime), 0), nil
}

// ExtractTraceLB extracts the tracelb line from scamper JSONL output,
// passed as data.
//
// As noted earlier, there are 4 lines in the output:
//   {"UUID":...}
//   {"type":"cycle-start"...}
//   {"type":"tracelb"...}
//   {"type":"cycle-stop"...}
func ExtractTraceLB(data []byte) (*TracelbLine, error) {
	var cycleStart cyclestartLine
	var tracelb TracelbLine
	var cycleStop cyclestopLine

	jsonStrings := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(jsonStrings) != 4 {
		return nil, errNumLines
	}

	// Validate the cycle-start line.
	err := json.Unmarshal([]byte(jsonStrings[1]), &cycleStart)
	if err != nil {
		return nil, errCycleStart
	}
	if cycleStart.Type != "cycle-start" {
		return nil, fmt.Errorf("%w: %v", errCycleStartType, cycleStart.Type)
	}

	// Validate the tracelb line.
	err = json.Unmarshal([]byte(jsonStrings[2]), &tracelb)
	if err != nil {
		return nil, errTracelb
	}
	if tracelb.Type != "tracelb" {
		return nil, fmt.Errorf("%w: %v", errTracelbType, tracelb.Type)
	}

	// Validate the cycle-stop line.
	err = json.Unmarshal([]byte(jsonStrings[3]), &cycleStop)
	if err != nil {
		return nil, errCycleStop
	}
	if cycleStop.Type != "cycle-stop" {
		return nil, fmt.Errorf("%w: %v", errCycleStopType, cycleStop.Type)
	}

	return &tracelb, nil
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
