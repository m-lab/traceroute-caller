package parser

import (
	"bytes"
	"errors"
	"log"
	"net"
	"os"

	"github.com/buger/jsonparser"
)

func init() {
	InitParserVersion()
}

var gParserVersion string

var (
	ErrNotTraceLB            = errors.New("not a tracelb record")
	ErrNoTypeField           = errors.New("no type field")
	ErrTypeNotAString        = errors.New("type is not a string")
	ErrWrongNumberRecords    = errors.New("wrong number of JSONL lines")
	ErrNoNodes               = errors.New("record has no node fields")
	ErrNoAddr                = errors.New("node has no addr fields")
	ErrInternalInconsistency = errors.New("link or node count doesn't match field")
	ErrInvalidIP             = errors.New("not an IP address")
)

// InitParserVersion initializes the gParserVersion variable for use by all parsers.
func InitParserVersion() string {
	release, ok := os.LookupEnv("RELEASE_TAG")
	if ok && release != "empty_tag" {
		gParserVersion = "https://github.com/m-lab/traceroute-caller/tree/" + release
	} else {
		hash := os.Getenv("COMMIT_HASH")
		if len(hash) >= 8 {
			gParserVersion = "https://github.com/m-lab/traceroute-caller/tree/" + hash[0:8]
		} else {
			gParserVersion = "local development"
		}
	}
	return gParserVersion
}

func getIP(data []byte) (net.IP, error) {
	// XXX convert to GetString
	addr, err := jsonparser.GetString(data, "addr")
	switch addr {
	case "*":
		// These are expected, and parse to <nil>
		return nil, nil
	default:
		switch err {
		case nil:
			// Parse the IP string, to avoid formatting variations.
			ip := net.ParseIP(string(addr))
			// XXX Not clear whether we should check this - perhaps leave it
			// for the caller to deal with.  In particular, we don't want
			// a bad IP address to interfere with annotating good IPs
			if ip.String() == "<nil>" {
				// This happens if the IP address is not parseable.
				// It likely means an error in scamper, or a change in scamper behavior
				return ip, ErrInvalidIP
			}
			return ip, nil
		case jsonparser.KeyPathNotFoundError:
			// This will only happen if there are NO address fields in the input.
			// It should not happen in normal scamper output.
			return nil, ErrNoAddr
		default:
			// This is unexpected - we only expect KeyPathNotFoundError
			log.Println(err)
			return nil, err
		}
	}
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

func ExtractHops(data []byte) ([]string, error) {
	hops := make(map[string]struct{}, 100)

	// XXX Should use single call to get all needed non-array fields, type, linkc, nodec
	recordType, err := jsonparser.GetString(data, "type")
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

	nodec, err := jsonparser.GetInt(data, "nodec")
	if err != nil {
		return nil, err
	}
	if nodec == 0 {
		return nil, ErrNoNodes
	}

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
				if ip != nil {
					hops[ip.String()] = struct{}{}
				}
			default:
			}

			// XXX - this may not be necessary, as it seems that there is a node for every IP address
			// and final links have destinations of "*"

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
							if ip != nil {
								hops[ip.String()] = struct{}{}
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
