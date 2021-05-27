package parser

import (
	"encoding/json"
	"errors"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-jsonnet"
	"github.com/m-lab/traceroute-caller/schema"
)

// Parse Scamper JSON filename like
// The format of JSON can be found at
// https://www.caida.org/tools/measurement/scamper/.
// NB: It is not clear where at that URL the format can be found.
// The structs here may just be derived from the actual scamper json files.
// scamper-cvs-20191102 trace/scamper_trace.h contains C structs that
// may be helpful for understanding this, though the structures are different
// from the JSON structure.

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
// The second line is defined in CyclestartLine
// The third line is defined in TracelbLine
// The fourth line is defined in CyclestopLine

// Metadata contains the UUID and other metadata provided by the traceroute-caller code.
type Metadata struct {
	UUID                    string `json:"UUID" binding:"required"`
	TracerouteCallerVersion string `json:"TracerouteCallerVersion"`
	CachedResult            bool   `json:"CachedResult"`
	CachedUUID              string `json:"CachedUUID"`
}

// CyclestartLine contains the information about the scamper "cyclestart"
type CyclestartLine struct {
	Type      string  `json:"type"`      // "cycle-start"
	ListName  string  `json:"list_name"` // e.g. "/tmp/scamperctrl:58"
	ID        float64 `json:"id"`        // e.g. 1 - seems to be an integer?
	Hostname  string  `json:"hostname"`
	StartTime float64 `json:"start_time"` // This is a unix epoch time.
}

// TracelbLine contains the actual scamper trace details.
// Not clear why so many fields are floats.  Fields in scamper code are uint16_t and uint8_t
type TracelbLine struct {
	Type    string  `json:"type"`
	Version string  `json:"version"`
	Userid  float64 `json:"userid"`
	Method  string  `json:"method"`
	Src     string  `json:"src"`
	Dst     string  `json:"dst"`
	Start   TS      `json:"start"`
	// NOTE: None of these seem to be actual floats - all ints.
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
	ID       float64 `json:"id"`
	Hostname string  `json:"hostname"`
	StopTime float64 `json:"stop_time"` // This is a unix epoch time.
}

// ParseRaw parses JSONL files containing the four JSON lines described above,
// into the TRC3.0 schema structs.
func ParseRaw(data []byte, connTime time.Time) (schema.PTTestRaw, error) {
	var uuid, version string
	var resultFromCache bool
	var hops []schema.ScamperHop
	var meta Metadata
	var cycleStart CyclestartLine
	var tracelb TracelbLine
	var cycleStop CyclestopLine

	jsonStrings := strings.Split(string(data[:]), "\n")
	if len(jsonStrings) != 5 {
		log.Println("Invalid test")
		return schema.PTTestRaw{}, errors.New("invalid test")
	}

	// Parse the first line for meta info.
	err := json.Unmarshal([]byte(jsonStrings[0]), &meta)

	if err != nil {
		log.Println(err)
		return schema.PTTestRaw{}, errors.New("invalid meta")
	}
	if meta.UUID == "" {
		return schema.PTTestRaw{}, errors.New("empty UUID")
	}
	uuid = meta.UUID
	version = meta.TracerouteCallerVersion
	resultFromCache = meta.CachedResult

	err = json.Unmarshal([]byte(jsonStrings[1]), &cycleStart)
	if err != nil {
		return schema.PTTestRaw{}, errors.New("invalid cycle-start")
	}

	// Parse the line in struct
	err = json.Unmarshal([]byte(jsonStrings[2]), &tracelb)
	if err != nil {
		// Some early stage scamper output has JSON grammar errors that can be fixed by
		// extra reprocessing using jsonnett
		// TODO: this is a hack. We should see if this can be simplified.
		vm := jsonnet.MakeVM()
		output, err := vm.EvaluateAnonymousSnippet("file", jsonStrings[2])
		if err != nil {
			return schema.PTTestRaw{}, errors.New("jsonnet also unable to parse json")
		}
		err = json.Unmarshal([]byte(output), &tracelb)
		if err != nil {
			// NB: It seems unlikely that this error will ever occur, since the json here
			// is generated by jsonnet VM.
			return schema.PTTestRaw{}, errors.New("invalid tracelb")
		}
	}
	for i := range tracelb.Nodes {
		oneNode := &tracelb.Nodes[i]
		var links []schema.HopLink
		if len(oneNode.Links) == 0 {
			hops = append(hops, schema.ScamperHop{
				Source: schema.HopIP{
					IP:       oneNode.Addr,
					Hostname: oneNode.Name},
				Linkc: oneNode.Linkc,
			})
			continue
		}
		if len(oneNode.Links) != 1 {
			continue
		}
		// Links is an array containing a single array of HopProbes.
		for _, oneLink := range oneNode.Links[0] {
			var probes []schema.HopProbe
			var ttl int64
			for _, oneProbe := range oneLink.Probes {
				var rtt []float64
				for _, oneReply := range oneProbe.Replies {
					rtt = append(rtt, oneReply.RTT)
				}
				probes = append(probes, schema.HopProbe{Flowid: int64(oneProbe.Flowid), Rtt: rtt})
				ttl = int64(oneProbe.TTL)
			}
			links = append(links, schema.HopLink{HopDstIP: oneLink.Addr, TTL: ttl, Probes: probes})
		}
		hops = append(hops, schema.ScamperHop{
			Source: schema.HopIP{IP: oneNode.Addr, Hostname: oneNode.Name},
			Linkc:  oneNode.Linkc,
			Links:  links,
		})
	}

	// XXX ^^^^^^ Everything above here is almost identical to the structs and
	// ParseJSONL code in etl/parser/pt.go

	err = json.Unmarshal([]byte(jsonStrings[3]), &cycleStop)
	if err != nil {
		return schema.PTTestRaw{}, errors.New("invalid cycle-stop")
	}

	output := schema.PTTestRaw{
		SchemaVersion:          "1",
		UUID:                   uuid,
		TestTime:               connTime,
		StartTime:              int64(cycleStart.StartTime),
		StopTime:               int64(cycleStop.StopTime),
		ScamperVersion:         tracelb.Version,
		ServerIP:               tracelb.Src,
		ClientIP:               tracelb.Dst,
		ProbeSize:              int64(tracelb.ProbeSize),
		ProbeC:                 int64(tracelb.Probec),
		Hop:                    hops,
		CachedResult:           resultFromCache,
		TracerouteCallerCommit: version,
	}
	return output, nil
}

// ParseJSON the raw jsonl test file into schema.PTTest.
// NB: This is NOT the scamper tool format.
func ParseJSON(testName string, rawContent []byte) (schema.PTTestRaw, error) {
	// Get the logtime
	logTime, err := GetLogtime(PTFileName{Name: filepath.Base(testName)})
	if err != nil {
		return schema.PTTestRaw{}, err
	}

	PTTest, err := ParseRaw(rawContent, logTime)

	if err != nil {
		return schema.PTTestRaw{}, err
	}
	PTTest.TestTime = logTime
	return PTTest, nil
}
