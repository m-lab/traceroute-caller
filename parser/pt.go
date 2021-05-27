package parser

// Much of this file is copied from code in etl/parser/pt.go.  This comment
// (just below) doesn't really belong here.  Node, ProcessAllNodes, Unique,
// ParseFirstLine, ParseOneTuple, and Parse are duplicated almost exactly
// from etl.  However, much of that code is for handling different "legacy"
// Paris traceroute data, and does not belong here.

// Parse PT filename like 20170320T23:53:10Z-98.162.212.214-53849-64.86.132.75-42677.paris
// The format of legacy test file can be found at https://paris-traceroute.net/.

import (
	"errors"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/m-lab/traceroute-caller/schema"
)

func init() {
	InitParserVersion()
}

var gParserVersion string

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

// PTFileName is the file name of paris-traceroute output.
type PTFileName struct {
	Name string
}

// GetDate coverts a date like "20170320T23:53:10Z" into the format "20170320T235310Z".
func (f *PTFileName) GetDate() (string, bool) {
	i := strings.Index(f.Name, "Z")
	if i >= 15 {
		return strings.Replace(f.Name[0:i+1], ":", "", -1), true
	}
	return "", false
}

// GetLogtime returns timestamp parsed from file name.
func GetLogtime(filename PTFileName) (time.Time, error) {
	date, success := filename.GetDate()
	if !success {
		return time.Time{}, errors.New("no date in filename")
	}

	return time.Parse("20060102T150405Z", date)
}

// cachedPTData is used to store the parsed results temporarily before it is verified
// not polluted and can be inserted into BQ tables
type cachedPTData struct {
	TestID           string
	Hops             []schema.ScamperHop
	LogTime          time.Time
	ServerIP         string
	ClientIP         string
	LastValidHopLine string
	UUID             string
}

// XXX vvvvvvv Largely copy paste from etl/parser/pt.go

// Node represents a hop.
// Copied/adapted from etl/parser/pt.go.
type Node struct {
	hostname       string
	ip             string
	rtts           []float64
	parentIP       string
	parentHostname string

	// For a given hop in a paris traceroute, there may be multiple IP
	// addresses. Each one belongs to a flow, which is an independent path from
	// the source to the destination IP. Some hops only have a single flow which
	// is given the -1 value. Any specific flows are numbered
	// sequentially starting from 0.
	flow int
}

// TODO: determine if IPv[46]AF constants are needed.

// IPv4AF is IPv4 address family.
const IPv4AF int32 = 2

// IPv6AF is IPv6 address family.
const IPv6AF int32 = 10

// PTBufferSize is the buffer size of paris-traceroute.
const PTBufferSize int = 2

// ProcessAllNodes takes an array of Nodes and generates one ScamperHop entry from each Node.
// Copied/adapted from etl/parser/pt.go.
func ProcessAllNodes(allNodes []Node, serverIP, protocol string) []schema.ScamperHop {
	var results []schema.ScamperHop

	// Iterate from the end of the list of nodes to minimize cost of removing nodes.
	for i := len(allNodes) - 1; i >= 0; i-- {
		oneProbe := schema.HopProbe{
			Rtt: allNodes[i].rtts,
		}
		probes := make([]schema.HopProbe, 0, 1)
		probes = append(probes, oneProbe)
		hopLink := schema.HopLink{
			HopDstIP: allNodes[i].ip,
			Probes:   probes,
		}
		links := make([]schema.HopLink, 0, 1)
		links = append(links, hopLink)
		if allNodes[i].parentIP == "" {
			// create a hop that from serverIP to allNodes[i].ip
			source := schema.HopIP{
				IP: serverIP,
			}
			oneHop := schema.ScamperHop{
				Source: source,
				Links:  links,
			}
			results = append(results, oneHop)
			break
		} else {
			source := schema.HopIP{
				IP:       allNodes[i].parentIP,
				Hostname: allNodes[i].parentHostname,
			}
			oneHop := schema.ScamperHop{
				Source: source,
				Links:  links,
			}
			results = append(results, oneHop)
		}
	}
	return results
}

// Unique was designed for hops with multiple flows. When the source
// IP are duplicate flows, but the destination IP is single flow IP, those
// hops will result in just one node in the list.
// Copied/adapted from etl/parser/pt.go.
func Unique(oneNode Node, list []Node) bool {
	for _, existingNode := range list {
		if existingNode.hostname == oneNode.hostname && existingNode.ip == oneNode.ip && existingNode.flow == oneNode.flow {
			return false
		}
	}
	return true
}

// ParseFirstLine handles the first line, like
// "traceroute [(64.86.132.76:33461) -> (98.162.212.214:53849)], protocol icmp, algo exhaustive, duration 19 s"
// Copied/adapted from etl/parser/pt.go.
func ParseFirstLine(oneLine string) (protocol string, destIP string, serverIP string, err error) {
	parts := strings.Split(oneLine, ",")
	// check protocol
	// check algo
	for index, part := range parts {
		if index == 0 {
			segments := strings.Split(part, " ")
			if len(segments) != 4 {
				return "", "", "", errors.New("corrupted first line")
			}
			if len(segments[1]) <= 2 || !strings.HasPrefix(segments[1], "[(") || len(segments[3]) <= 2 || !strings.HasPrefix(segments[3], "(") {
				return "", "", "", errors.New("invalid data format in the first line")
			}
			serverIPIndex := strings.LastIndex(segments[1], ":")
			destIPIndex := strings.LastIndex(segments[3], ":")
			if serverIPIndex < 3 || destIPIndex < 2 {
				return "", "", "", errors.New("invalid data format in the first line")
			}
			serverIP = segments[1][2:serverIPIndex]
			destIP = segments[3][1:destIPIndex]
			if net.ParseIP(serverIP) == nil || net.ParseIP(destIP) == nil {
				return "", "", "", errors.New("invalid IP address in the first line")
			}
			continue
		}
		mm := strings.Split(strings.TrimSpace(part), " ")
		if len(mm) > 1 {
			if mm[0] == "algo" {
				if mm[1] != "exhaustive" {
					log.Printf("Unexpected algorithm")
				}
			}
			if mm[0] == "protocol" {
				if mm[1] != "icmp" && mm[1] != "udp" && mm[1] != "tcp" {
					log.Printf("Unknown protocol")
					return "", "", "", errors.New("unknown protocol")
				}
				protocol = mm[1]
			}
		}
	}
	return protocol, destIP, serverIP, nil
}

// CreateTestID creates a test ID based on the given file name and test name.
// fn is in format like 20170501T000000Z-mlab1-acc02-paris-traceroute-0000.tgz
// bn is in format like 20170320T23:53:10Z-98.162.212.214-53849-64.86.132.75-42677.paris
// test_id is in format like 2017/05/01/mlab1.lga06/20170501T23:58:07Z-72.228.158.51-40835-128.177.119.209-8080.paris.gz
// Copied/adapted from etl/parser/pt.go.
func CreateTestID(fn string, bn string) string {
	rawFn := filepath.Base(fn)
	testID := bn
	if len(rawFn) > 30 {
		testID = rawFn[0:4] + "/" + rawFn[4:6] + "/" + rawFn[6:8] + "/" + rawFn[17:22] + "." + rawFn[23:28] + "/" + bn + ".gz"
	}
	return testID
}

// ProcessOneTuple processes a tuple. For each 4 tuples, it is like:
// parts[0] is the hostname, like "if-ae-10-3.tcore2.DT8-Dallas.as6453.net".
// parts[1] is IP address like "(66.110.57.41)" or "(72.14.218.190):0,2,3,4,6,8,10"
// parts[2] are rtt in numbers like "0.298/0.318/0.340/0.016"
// parts[3] should always be "ms"
// Copied/adapted from etl/parser/pt.go.
func ProcessOneTuple(parts []string, protocol string, currentLeaves []Node, allNodes, newLeaves *[]Node) error {
	if parts[3] != "ms" {
		return errors.New("malformed line - Expected 'ms'")
	}
	var rtt []float64
	// TODO: to use regexp here.
	switch {
	// Handle tcp or udp, parts[2] is a single number.
	case protocol == "tcp" || protocol == "udp":
		oneRtt, err := strconv.ParseFloat(parts[2], 64)
		if err == nil {
			rtt = append(rtt, oneRtt)
		} else {
			log.Printf("Failed to conver rtt to number with error %v", err)
			return err
		}

	// Handle icmp, parts[2] has 4 numbers separated by "/"
	case protocol == "icmp":
		nums := strings.Split(parts[2], "/")
		if len(nums) != 4 {
			return errors.New("failed to parse rtts for icmp test - 4 numbers expected")
		}
		for _, num := range nums {
			oneRtt, err := strconv.ParseFloat(num, 64)
			if err == nil {
				rtt = append(rtt, oneRtt)
			} else {
				log.Printf("Failed to conver rtt to number with error %v", err)
				return err
			}
		}
	}
	// check whether it is single flow or mulitple flows
	// sample of multiple flows: (72.14.218.190):0,2,3,4,6,8,10
	// sample of single flows: (172.25.252.166)
	ips := strings.Split(parts[1], ":")

	// Check whether it is root node.
	if len(*allNodes) == 0 {
		oneNode := &Node{
			hostname: parts[0],
			ip:       ips[0][1 : len(ips[0])-1],
			rtts:     rtt,
			parentIP: "",
			flow:     -1,
		}

		*allNodes = append(*allNodes, *oneNode)
		*newLeaves = append(*newLeaves, *oneNode)
		return nil
	}
	// There are duplicates in allNodes, but not in newLeaves.
	// TODO(dev): consider consolidating these with a repeat count.
	switch len(ips) {
	case 1:
		// For single flow, the new node will be son of all current leaves
		for _, leaf := range currentLeaves {
			oneNode := &Node{
				hostname:       parts[0],
				ip:             ips[0][1 : len(ips[0])-1],
				rtts:           rtt,
				parentIP:       leaf.ip,
				parentHostname: leaf.hostname,
				flow:           -1,
			}
			*allNodes = append(*allNodes, *oneNode)
			if Unique(*oneNode, *newLeaves) {
				*newLeaves = append(*newLeaves, *oneNode)
			}
		}
	case 2:
		// Create a leave for each flow.
		flows := strings.Split(ips[1], ",")
		for _, flow := range flows {
			flowInt, err := strconv.Atoi(flow)
			if err != nil {
				return err
			}

			for _, leaf := range currentLeaves {
				if leaf.flow == -1 || leaf.flow == flowInt {
					oneNode := &Node{
						hostname:       parts[0],
						ip:             ips[0][1 : len(ips[0])-1],
						rtts:           rtt,
						parentIP:       leaf.ip,
						parentHostname: leaf.hostname,
						flow:           flowInt,
					}
					*allNodes = append(*allNodes, *oneNode)
					if Unique(*oneNode, *newLeaves) {
						*newLeaves = append(*newLeaves, *oneNode)
					}
				}
			}
		}
	default:
		return errors.New("wrong format for flow IP address")
	}
	return nil
}

// Parse the raw test file into hops ParisTracerouteHop.
// Copied/adapted from etl/parser/pt.go.
func Parse(fileName string, testName string, testID string, rawContent []byte) (cachedPTData, error) {
	//log.Printf("%s", testName)

	// Get the logtime
	fn := PTFileName{Name: filepath.Base(testName)}
	// Check whether the file name format is old format ("20160221T23:43:25Z_ALL27695.paris")
	// or new 5-tuple format ("20170501T23:53:10Z-98.162.212.214-53849-64.86.132.75-42677.paris").
	destIP := ""
	serverIP := ""
	// We do not need to get destIP and serverIP from file name, since they are at the first line
	// of test content as well.
	logTime, err := GetLogtime(fn)
	if err != nil {
		return cachedPTData{}, err
	}

	// The filename contains 5-tuple like 20170320T23:53:10Z-98.162.212.214-53849-64.86.132.75-42677.paris
	// By design, they are logtime, local IP, local port, the server IP and port which served the test
	// that triggered this PT test (not the server IP & port that served THIS PT test.)
	isFirstLine := true
	protocol := "icmp"
	// This var keep all current leaves
	var currentLeaves []Node
	// This var keep all possible nodes
	var allNodes []Node
	// TODO(dev): Handle the first line explicitly before this for loop,
	// then run the for loop on the remainder of the slice.
	lastValidHopLine := ""
	reachedDest := false
	for _, oneLine := range strings.Split(string(rawContent[:]), "\n") {
		oneLine = strings.TrimSuffix(oneLine, "\n")
		// Skip empty line or initial lines starting with #.
		if len(oneLine) == 0 || oneLine[0] == '#' {
			continue
		}
		// This var keep all new leaves
		var newLeaves []Node
		if isFirstLine {
			isFirstLine = false
			var err error
			protocol, destIP, serverIP, err = ParseFirstLine(oneLine)
			if err != nil {
				log.Printf("%s %s", oneLine, testName)
				return cachedPTData{}, err
			}
		} else {
			// Handle each line of test file after the first line.
			// TODO(dev): use regexp here
			parts := strings.Fields(oneLine)
			// Skip line start with "MPLS"
			if len(parts) < 4 || parts[0] == "MPLS" {
				continue
			}

			// Drop the first 3 parts, like "1  P(6, 6)" because they are useless.
			// The following parts are grouped into tuples, each with 4 parts:
			for i := 3; i < len(parts); i += 4 {
				if (i + 3) >= len(parts) {
					// avoid panic crash due to corrupted content
					break
				}
				tupleStr := []string{parts[i], parts[i+1], parts[i+2], parts[i+3]}
				err := ProcessOneTuple(tupleStr, protocol, currentLeaves, &allNodes, &newLeaves)
				if err != nil {
					return cachedPTData{}, err
				}
				// Skip over any error codes for now. These are after the "ms" and start with '!'.
				for ; i+4 < len(parts) && parts[i+4] != "" && parts[i+4][0] == '!'; i++ {
				}
			} // Done with a 4-tuple parsing
			if strings.Contains(oneLine, destIP) {
				reachedDest = true
				// TODO: It is an option that we just stop parsing
			}
			// lastValidHopLine is the last line from raw test file that contains valid hop information.
			lastValidHopLine = oneLine
		} // Done with one line
		currentLeaves = newLeaves
	} // Done with a test file

	if len(allNodes) == 0 {
		// Empty test, stop here.
		return cachedPTData{}, errors.New("empty test")
	}
	// Check whether the last hop is the destIP

	if allNodes[len(allNodes)-1].ip != destIP && !strings.Contains(lastValidHopLine, destIP) {
		// This is the case that we consider the test did not reach destIP at the last hop.
		if reachedDest {
			// This test reach dest in the middle, but then do weird things for unknown reason.
			log.Printf("middle mess up test_id: " + fileName + " " + testName)
		}
	} else {
		lastValidHopLine = "ExpectedDestIP"
	}

	// Generate Hops from allNodes
	PTHops := ProcessAllNodes(allNodes, serverIP, protocol)

	// TODO: Add annotation to the IP of source, destination and hops.

	return cachedPTData{
		TestID:           testID,
		Hops:             PTHops,
		LogTime:          logTime,
		ServerIP:         serverIP,
		ClientIP:         destIP,
		LastValidHopLine: lastValidHopLine,
	}, nil
}

// XXX ^^^^^^^ Largely copy paste from etl/parser/pt.go

// PTParser encapsulates data for a paris-traceroute measurement.
type PTParser struct {
	// Care should be taken to ensure this does not accumulate many rows and
	// lead to OOM problems.
	previousTests []cachedPTData
	taskFileName  string // The tar file containing these tests.
	NumFiles      int    // Number of files already written
}

// ParseAndWrite parses a paris-traceroute log file and write the output in a json file.
func (pt *PTParser) ParseAndWrite(fileName string, testName string, rawContent []byte) error {
	if fileName == "" {
		return errors.New("empty filename")
	}
	testID := CreateTestID(fileName, filepath.Base(testName))
	pt.taskFileName = fileName

	// Process the legacy Paris Traceroute txt output
	// XXX Why is this considered legacy?
	cachedTest, err := Parse(fileName, testName, testID, rawContent)
	if err != nil {
		log.Printf("%v %s", err, testName)
		return err
	}

	// Check all buffered PT tests whether Client_ip in connSpec appear in
	// the last hop of the buffered test.
	// If it does appear, then the buffered test was polluted, and it will
	// be discarded from buffer.
	// If it does not appear, then no pollution detected.
	destIP := cachedTest.ClientIP
	for index, PTTest := range pt.previousTests {
		// array of hops was built in reverse order from list of nodes
		// (in func ProcessAllNodes()). So the final parsed hop is Hops[0].
		finalHop := PTTest.Hops[0]
		if PTTest.ClientIP != destIP && len(finalHop.Links) > 0 &&
			(finalHop.Links[0].HopDstIP == destIP || strings.Contains(PTTest.LastValidHopLine, destIP)) {
			// Discard pt.previousTests[index]
			pt.previousTests = append(pt.previousTests[:index], pt.previousTests[index+1:]...)
			break
		}
	}

	// If a test ends at the expected DestIP, it is not at risk of being
	// polluted,so we don't have to wait to check against further tests.
	// We can just go ahead and insert it to BigQuery table directly. This
	// optimization makes the pollution check more effective by saving the
	// unnecessary check between those tests (reached expected DestIP) and
	// the new test.
	// Also we don't care about test LogTime order, since there are other
	// workers inserting other blocks of hops concurrently.
	if cachedTest.LastValidHopLine == "ExpectedDestIP" {
		pt.WriteOneTest(cachedTest)
		return nil
	}

	// If buffer is full, remove the oldest test and insert it into BigQuery table.
	if len(pt.previousTests) >= PTBufferSize {
		// Insert the oldest test pt.previousTests[0] into BigQuery
		pt.WriteOneTest(pt.previousTests[0])
		pt.previousTests = pt.previousTests[1:]
	}
	// Insert current test into pt.previousTests
	pt.previousTests = append(pt.previousTests, cachedTest)
	return nil
}

// WriteOneTest annotates the IPs and writes the file to disk.
func (pt *PTParser) WriteOneTest(oneTest cachedPTData) {
	// TODO: Annotate the IPs and write the file to Disk
	/*
		parseInfo := schema.ParseInfo{
			TaskFileName:  pt.taskFileName,
			ParseTime:     time.Now(),
			ParserVersion: Version(),
			Filename:      oneTest.TestID,
		}

		ptTest := schema.PTTest{
			UUID:        oneTest.UUID,
			TestTime:    oneTest.LogTime,
			Parseinfo:   parseInfo,
			Source:      oneTest.Source,
			Destination: oneTest.Destination,
			Hop:         oneTest.Hops,
		}


		err := pt.AddRow(&ptTest)
	*/
	pt.NumFiles++
}

// TODO: These exported methods are only used for unit tests but if
//       tests do whitebox testing there is no need for these.

// NumBufferedTests returns the number of previous tests.
func (pt *PTParser) NumBufferedTests() int {
	return len(pt.previousTests)
}

// NumFilesForTests returns the number of test files already written.
func (pt *PTParser) NumFilesForTests() int {
	return pt.NumFiles
}
