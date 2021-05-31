// parser package handles parsing of scamper JSONL.
// The format of JSON can be found at
// https://www.caida.org/tools/measurement/scamper/.
// NB: It is not clear where at that URL the format can be found.
// The structs here may just be derived from the actual scamper json files.
// scamper-cvs-20191102 trace/scamper_trace.h contains C structs that
// may be helpful for understanding this, though the structures are different
// from the JSON structure.
package parser

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"net"

	"github.com/buger/jsonparser"
)

var (
	ErrNotTraceLB         = errors.New("not a tracelb record")
	ErrNoTypeField        = errors.New("no type field")
	ErrTypeNotAString     = errors.New("type is not a string")
	ErrWrongNumberRecords = errors.New("wrong number of JSONL lines")
	ErrNoNodes            = errors.New("record has no node fields")
	ErrNoAddr             = errors.New("node has no addr fields")
	ErrBadLinkC           = errors.New("linkc field does not match")
	ErrInvalidIP          = errors.New("not an IP address")
)

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
//   CyclestartLine
//   TracelbLine
//   CyclestopLine

// CyclestartLine contains the information about the scamper "cyclestart"
type CyclestartLine struct {
	Type      string  `json:"type"`      // "cycle-start"
	ListName  string  `json:"list_name"` // e.g. "/tmp/scamperctrl:58"
	ID        float64 `json:"id"`        // XXX Integer?
	Hostname  string  `json:"hostname"`
	StartTime float64 `json:"start_time"` // XXX Integer? This is a unix epoch time.
}

// TracelbLine contains the actual scamper trace details.
// Not clear why so many fields are floats.  Fields in scamper code are uint16_t and uint8_t
type TracelbLine struct {
	Type    string  `json:"type"`
	Version string  `json:"version"`
	Userid  float64 `json:"userid"` // TODO change to int?
	Method  string  `json:"method"`
	Src     string  `json:"src"`
	Dst     string  `json:"dst"`
	Start   TS      `json:"start"`
	// TODO - None of these seem to be actual floats - change to int?
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
	Type     string  `json:"type"` // "cycle-stop"
	ListName string  `json:"list_name"`
	ID       float64 `json:"id"` // TODO - change to int?
	Hostname string  `json:"hostname"`
	StopTime float64 `json:"stop_time"` // This is a unix epoch time.
}

// XXX ^^^^^^ Everything above here is almost identical to the structs and
// ParseJSONL code in etl/parser/pt.go

// ExtractHops1 parses tracelb and extract all hop addresses.
func ExtractHops1(tracelb *TracelbLine) ([]string, error) {
	// Unfortunately, net.IP cannot be used as map key.
	hops := make(map[string]struct{}, 100)

	// Parse the json into struct
	for i := range tracelb.Nodes {
		node := &tracelb.Nodes[i]
		hops[node.Addr] = struct{}{}
		for j := range node.Links {
			links := node.Links[j]
			for k := range links {
				link := &links[k]
				// Parse the IP string, to avoid formatting variations.
				ip := net.ParseIP(link.Addr)
				if ip.String() != "" {
					hops[ip.String()] = struct{}{}
				}
			}
		}
	}
	hopStrings := make([]string, 0, len(hops))
	for h := range hops {
		hopStrings = append(hopStrings, h)
	}
	return hopStrings, nil
}

func getIP(data []byte) (net.IP, error) {
	// XXX convert to GetString
	addr, inner := jsonparser.GetString(data, "addr")
	switch inner {
	case nil:
		// Parse the IP string, to avoid formatting variations.
		ip := net.ParseIP(string(addr))
		// There seems to be a problem letting through <nil> values
		if ip.String() != "" && ip.String() != "<nil>" {
			return ip, nil
		}
		return ip, ErrInvalidIP
	case jsonparser.KeyPathNotFoundError:
		// This will only happen if there are NO address fields in the whole node.
		// Should we instead look for link fields?
		log.Println("addr field not found")
		return nil, ErrNoAddr
	default:
		log.Println(inner)
		return nil, inner
	}
}

func ExtractHops(data []byte) ([]string, error) {
	hops := make(map[string]struct{}, 100)

	// XXX Should use single call to get all needed non-array fields, type, linkc, nodec
	recordType, err := jsonparser.GetString(data, "type")
	switch err {
	case nil:
	case jsonparser.KeyPathNotFoundError:
		return nil, ErrNoTypeField
	default:
		return nil, err
	}
	if string(recordType) != "tracelb" {
		return nil, ErrNotTraceLB
	}

	linkc, err := jsonparser.GetInt(data, "linkc")
	if err != nil {
		return nil, err
	}

	var addrErr error
	_, err = jsonparser.ArrayEach(data, func(nodeValue []byte, dataType jsonparser.ValueType, offset int, err error) {
		log.Println("node")
		ip, e1 := getIP(nodeValue)
		switch e1 {
		case nil:
			log.Println(" -  addr", ip.String())
			hops[ip.String()] = struct{}{}
		default:
		}
		// links is an array containing more arrays...
		_, linkErr1 := jsonparser.ArrayEach(nodeValue,
			func(linksValue []byte, datatype jsonparser.ValueType, offset int, err error) {
				_, linkErr2 := jsonparser.ArrayEach(nodeValue,
					func(linksValue []byte, datatype jsonparser.ValueType, offset int, err error) {
						log.Println("  link")
						addr, inner := jsonparser.GetString(linksValue, "addr")
						switch inner {
						case nil:
							ip := net.ParseIP(string(addr))
							log.Println(" +  addr", ip.String())
							// There seems to be a problem letting through <nil> values
							if ip.String() != "" && ip.String() != "<nil>" {
								hops[ip.String()] = struct{}{}
							}
						case jsonparser.KeyPathNotFoundError:
							// This will only happen if there are NO address fields in the whole node.
							// Should we instead look for link fields?
							log.Println("addr field not found", string(linksValue))
							addrErr = ErrNoAddr
						default:
							log.Println(inner)
							addrErr = inner
						}

					}, "")
				if linkErr2 != nil {
					panic(linkErr2)
				}
			}, "links")
		if linkErr1 != nil {
			panic(linkErr1)
		}
	}, "nodes")

	switch err {
	case nil: // do nothing
	case jsonparser.KeyPathNotFoundError:
		return nil, ErrNoNodes
	default:
		return nil, err
	}
	if addrErr != nil {
		log.Println("addr error", addrErr)
		return nil, addrErr
	}

	hopStrings := make([]string, 0, len(hops))
	for h := range hops {
		hopStrings = append(hopStrings, h)
	}
	if int(linkc) != len(hops) {
		return hopStrings, ErrBadLinkC
	}
	return hopStrings, nil
}

// ExtractTraceLB extracts the traceLB line from scamper JSONL.
// Not currently used, but expected to be used soon for hop annotations.
func ExtractTraceLB(data []byte) (*TracelbLine, error) {
	var cycleStart CyclestartLine
	var cycleStop CyclestopLine
	sep := []byte{'\n'}

	jsonLines := bytes.Split(data, sep)
	//jsonStrings := strings.Split(string(data), "\n")
	if len(jsonLines) != 3 && (len(jsonLines) != 4 || len(jsonLines[3]) != 0) {
		return nil, ErrWrongNumberRecords
	}

	// TODO These (cycleStart/Stop checking) are not strictly necessary.  We'll keep them for a while for
	// debugging, but will likely remove them soon, as they provide little value.
	err := json.Unmarshal(jsonLines[0], &cycleStart)
	if err != nil {
		return nil, errors.New("invalid cycle-start")
	}

	err = json.Unmarshal(jsonLines[2], &cycleStop)
	if err != nil {
		return nil, errors.New("invalid cycle-stop")
	}

	var tracelb TracelbLine
	err = json.Unmarshal(jsonLines[1], &tracelb)
	if err != nil {
		return nil, errors.New("invalid tracelb")
	}
	return &tracelb, nil
}

func ExtractTraceLine(data []byte) ([]byte, error) {
	sep := []byte{'\n'}

	jsonLines := bytes.Split(data, sep)
	//jsonStrings := strings.Split(string(data), "\n")
	if len(jsonLines) != 3 && (len(jsonLines) != 4 || len(jsonLines[3]) != 0) {
		return nil, errors.New("test has wrong number of lines")
	}

	return jsonLines[1], nil
}
