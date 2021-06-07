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
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/buger/jsonparser"
	"github.com/m-lab/go/rtx"
)

var (
	ErrNoTypeField           = errors.New("no type field")
	ErrNotTraceLB            = errors.New("not a tracelb record")
	ErrTypeNotAString        = errors.New("type is not a string")
	ErrWrongNumberRecords    = errors.New("wrong number of JSONL lines")
	ErrNoNodes               = errors.New("record has no node fields")
	ErrNoAddr                = errors.New("node has no addr fields")
	ErrInternalInconsistency = errors.New("link or node count doesn't match field")
	ErrInvalidIP             = errors.New("not an IP address")
)

var validateIPs = false

func getAddrString(data []byte) (string, error) {
	addr, err := jsonparser.GetString(data, "addr")
	switch err {
	case nil:
		return addr, nil
	case jsonparser.KeyPathNotFoundError:
		// This will only happen if there are NO address fields in the input.
		// It should not happen in normal scamper output.
		return "", ErrNoAddr
	default:
		// This is unexpected - we only expect KeyPathNotFoundError
		log.Println(err)
		return "", err
	}

}

func getIP(data []byte) (string, error) {
	addr, err := getAddrString(data)
	if err != nil {
		return "", err
	}
	if addr == "*" {
		return "", nil
	}
	if validateIPs {
		// Parse the IP string, to avoid formatting variations.
		ip := net.ParseIP(string(addr))
		// XXX Not clear whether we should check this - perhaps leave it
		// for the caller to deal with.  In particular, we don't want
		// a bad IP address to interfere with annotating good IPs
		if ip.String() == "<nil>" {
			// This happens if the IP address is not parseable.
			// It likely means an error in scamper, or a change in scamper behavior
			return "", ErrInvalidIP
		}
		return ip.String(), nil
	}
	return addr, nil
}

// ExtractTraceLine extracts the second of three lines in a scamper JSONL record,
// and verifies that it is a tracelb record.
func ExtractTraceLine(data []byte) ([]byte, error) {
	sep := []byte{'\n'}

	jsonLines := bytes.Split(data, sep)
	//jsonStrings := strings.Split(string(data), "\n")
	if len(jsonLines) != 3 && (len(jsonLines) != 4 || len(jsonLines[3]) != 0) {
		return nil, errors.New("test has wrong number of lines")
	}

	// XXX Should use single call to get all needed non-array fields, type, linkc, nodec
	recordType, err := jsonparser.GetString(jsonLines[1], "type")
	switch err {
	case nil: // Normal behavior
	case jsonparser.KeyPathNotFoundError:
		return nil, ErrNoTypeField
	default:
		return nil, err
	}
	if string(recordType) != "tracelb" {
		return nil, ErrNotTraceLB
	}

	return jsonLines[1], nil
}

var parseLinks = false

// ExtractHops extracts the hop IP address from nodes in a tracelb json record.
func ExtractHops(data []byte) ([]string, error) {

	nodec, err := jsonparser.GetInt(data, "nodec")
	if err != nil {
		return nil, err
	}
	if nodec == 0 {
		return nil, ErrNoNodes
	}
	hops := make(map[string]struct{}, nodec)

	//	linkc, err := jsonparser.GetInt(data, "linkc")
	//	if err != nil {
	//		return nil, err
	//	}

	//	nodeCount := 0
	//	linkCount := 0

	var addrErr error // Not really happy with this.  Better way?

	_, err = jsonparser.ArrayEach(data,
		func(nodeValue []byte, dataType jsonparser.ValueType, offset int, err error) {
			//		nodeCount++
			ip, e1 := getIP(nodeValue)
			switch e1 {
			case nil:
				if ip != "" {
					hops[ip] = struct{}{}
				}
			default:
			}
			// XXX - this may not be necessary, as it seems that there is a node for every IP address
			// and final links have destinations of "*"

			if parseLinks {
				// links is an array containing another unnamed array...
				_, linkErr1 := jsonparser.ArrayEach(nodeValue,
					func(linksValue []byte, datatype jsonparser.ValueType, offset int, err error) {
						//				linkCount++
						// Parser the inner array
						_, linkErr2 := jsonparser.ArrayEach(linksValue,
							func(linksValue2 []byte, datatype jsonparser.ValueType, offset int, err error) {
								ip, ipErr := getIP(linksValue2)
								if ipErr != nil {
									addrErr = ipErr
									return
								}
								if ip != "" {
									hops[ip] = struct{}{}
								}
							}) // No key, because the array in unnamed
						if linkErr2 != nil {
							// XXX Add a metric
							log.Println(linkErr2, string(linksValue))
						}
					}, "links")
				if linkErr1 != nil {
					// XXX Add a metric
					log.Println(linkErr1, string(nodeValue))
				}
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

	// It seems we don't actually understand the relationship between nodec/linkc
	// and the number of parsed elements.
	//
	//	if int(linkc) != linkCount || int(nodec) != nodeCount {
	//		log.Printf("%d/%d, %d/%d\n", nodeCount, nodec, linkCount, linkc)
	//		return hopStrings, ErrInternalInconsistency
	//	}
	return hopStrings, nil
}

// ExtractHops2 extracts all IP addresses from scamper's output in JSON format.
func ExtractHops2(data []byte) ([]string, error) {
	// "nodes" -> "addr": "172.19.0.1",
	nodec, err := jsonparser.GetInt(data, "nodec")
	if err != nil {
		log.Println("failed to parse nodec")
		return nil, err
	}
	hops := make([]string, 0, nodec)

	// "src": "172.19.0.2",
	// "dst": "172.24.129.116",
	if false {
		// We don't need the src and destination.  Those are already annotated by the uuid-annotator.
		// We might want to discard the dst address, if it shows up on the links.  It should
		// not show up in the nodes.
		for _, s := range []string{"src", "dst"} {
			hop, err := jsonparser.GetString(data, s)
			rtx.Must(err, "failed to parse "+s)
			addHop(&hops, hop)
		}
	}

	if parseLinks {
		for i := 0; i < int(nodec)-1; i++ {
			hop, err := jsonparser.GetString(data, "nodes", fmt.Sprintf("[%d]", i), "addr")
			if err != nil {
				log.Printf("failed to parse nodes[%d].addr", i)
				return nil, err
			}
			addHop(&hops, hop)
		}
	}

	// "nodes" -> "links" -> "addr": "100.116.79.252",
	linkc, err := jsonparser.GetInt(data, "linkc")
	rtx.Must(err, "failed to parse linkc")
	for i := 0; i < int(linkc); i++ {
		hop, err := jsonparser.GetString(data, "nodes", fmt.Sprintf("[%d]", i), "links", "[0]", "[0]", "addr")
		if err != nil {
			log.Printf("failed to parse nodes[%d].links[0][0].addr", i)
			return nil, err
		}
		addHop(&hops, hop)
	}

	return hops, nil
}

func addHop(hops *[]string, hop string) {
	for _, h := range *hops {
		if h == hop {
			return
		}
	}
	*hops = append(*hops, hop)
}
