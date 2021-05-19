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
// The format of JSON can be found at https://www.caida.org/tools/measurement/scamper/.

type TS struct {
	Sec  int64 `json:"sec"`
	Usec int64 `json:"usec"`
}

type Reply struct {
	Rx         TS      `json:"rx"`
	Ttl        int     `json:"ttl"`
	Rtt        float64 `json:"rtt"`
	Icmp_type  int     `json:"icmp_type"`
	Icmp_code  int     `json:"icmp_code"`
	Icmp_q_tos int     `json:"icmp_q_tos"`
	Icmp_q_ttl int     `json:"icmp_q_ttl"`
}

type Probe struct {
	Tx      TS      `json:"tx"`
	Replyc  int     `json:"replyc"`
	Ttl     int64   `json:"ttl"`
	Attempt int     `json:"attempt"`
	Flowid  int64   `json:"flowid"`
	Replies []Reply `json:"replies"`
}

type ScamperLink struct {
	Addr   string  `json:"addr"`
	Probes []Probe `json:"probes"`
}

type ScamperNode struct {
	Addr  string          `json:"addr"`
	Name  string          `json:"name"`
	Q_ttl int             `json:"q_ttl"`
	Linkc int64           `json:"linkc"`
	Links [][]ScamperLink `json:"links"`
}

// There are 4 lines in the traceroute test .jsonl file.
// The first line is defined in Metadata
// The second line is defined in CyclestartLine
// The third line is defined in TracelbLine
// The fourth line is defined in CyclestopLine

type Metadata struct {
	UUID                    string `json:"UUID" binding:"required"`
	TracerouteCallerVersion string `json:"TracerouteCallerVersion"`
	CachedResult            bool   `json:"CachedResult"`
	CachedUUID              string `json:"CachedUUID"`
}

type CyclestartLine struct {
	Type       string  `json:"type"`
	List_name  string  `json:"list_name"`
	ID         float64 `json:"id"`
	Hostname   string  `json:"hostname"`
	Start_time float64 `json:"start_time"`
}

type TracelbLine struct {
	Type         string        `json:"type"`
	Version      string        `json:"version"`
	Userid       float64       `json:"userid"`
	Method       string        `json:"method"`
	Src          string        `json:"src"`
	Dst          string        `json:"dst"`
	Start        TS            `json:"start"`
	Probe_size   float64       `json:"probe_size"`
	Firsthop     float64       `json:"firsthop"`
	Attempts     float64       `json:"attempts"`
	Confidence   float64       `json:"confidence"`
	Tos          float64       `json:"tos"`
	Gaplint      float64       `json:"gaplint"`
	Wait_timeout float64       `json:"wait_timeout"`
	Wait_probe   float64       `json:"wait_probe"`
	Probec       float64       `json:"probec"`
	Probec_max   float64       `json:"probec_max"`
	Nodec        float64       `json:"nodec"`
	Linkc        float64       `json:"linkc"`
	Nodes        []ScamperNode `json:"nodes"`
}

type CyclestopLine struct {
	Type      string  `json:"type"`
	List_name string  `json:"list_name"`
	ID        float64 `json:"id"`
	Hostname  string  `json:"hostname"`
	Stop_time float64 `json:"stop_time"`
}

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
			return schema.PTTestRaw{}, errors.New("invalid tracelb")
		}
		err = json.Unmarshal([]byte(output), &tracelb)
		if err != nil {
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
					rtt = append(rtt, oneReply.Rtt)
				}
				probes = append(probes, schema.HopProbe{Flowid: int64(oneProbe.Flowid), Rtt: rtt})
				ttl = int64(oneProbe.Ttl)
			}
			links = append(links, schema.HopLink{HopDstIP: oneLink.Addr, TTL: ttl, Probes: probes})
		}
		hops = append(hops, schema.ScamperHop{
			Source: schema.HopIP{IP: oneNode.Addr, Hostname: oneNode.Name},
			Linkc:  oneNode.Linkc,
			Links:  links,
		})
	}

	err = json.Unmarshal([]byte(jsonStrings[3]), &cycleStop)
	if err != nil {
		return schema.PTTestRaw{}, errors.New("invalid cycle-stop")
	}

	output := schema.PTTestRaw{
		SchemaVersion:          "1",
		UUID:                   uuid,
		TestTime:               connTime,
		StartTime:              int64(cycleStart.Start_time),
		StopTime:               int64(cycleStop.Stop_time),
		ScamperVersion:         tracelb.Version,
		ServerIP:               tracelb.Src,
		ClientIP:               tracelb.Dst,
		ProbeSize:              int64(tracelb.Probe_size),
		ProbeC:                 int64(tracelb.Probec),
		Hop:                    hops,
		CachedResult:           resultFromCache,
		TracerouteCallerCommit: version,
	}
	return output, nil
}

// ParseJSON the raw jsonl test file into schema.PTTest.
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
