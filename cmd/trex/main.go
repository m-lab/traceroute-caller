package main

import (
	"flag"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"

	"github.com/m-lab/traceroute-caller/parser"
)

var (
	prComplete = flag.Bool("c", false, "print flow IDs and file names of traceroutes that completed (\"--\" for incomplete traceroutes)")
	duration   = flag.Uint("d", 0, "print times and file names of traceroutes that took more than the specified duration")
	examples   = flag.Bool("e", false, "print examples how to use this tool and exit")
	verbose    = flag.Bool("v", false, "enable verbose mode (mostly for debugging)")
	flagSet    = make(map[string]bool)

	// Statistics printed before exiting.
	nFilesFound   uint32 // files found
	nFilesSkipped uint32 // files skipped (not .jsonl)
	nReadErrors   uint32 // files that couldn't be read
	nParseErrors  uint32 // files that couldn't be parsed
	nFilesParsed  uint32 // files successfully parsed
	nNoTraceroute uint32 // files with no traceroute data
	nCompletes    uint32 // files with complete traceroutes (i.e., traceroute reaches destination)
	minDuration   uint32 // minimum traceroute duration
	maxDuration   uint32 // maximum traceroute duration
	totDuration   uint64 // total duration of all traceroutes
)

// Hop defines a hop.
type Hop struct {
	addr     string    // hop's IP address in string format
	flowid   int64     // flowid is a positive integer, generally starting from 1
	ttl      int       // time to live
	tx       []int64   // probe transmit time after tracelb start time in milliseconds
	rx       []int64   // probe receive time after tracelb start time in milliseconds
	rtt      []float64 // round trip time in milliseconds
	complete bool      // route is complete and reaches destination
}

// We have to use a custom usage() function because m-lab/traceroute-caller/parser
// ends up pulling in m-lab/go/prometheusx and m-lab/uuid which have package-level
// flags -prometheusx.listen-address and -uuid-prefix-file respectively but these
// flags are irrelevant for this tool and confuse the user if printed.
func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [-cehv] [-d <seconds>] path [path...]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "path  a pathname to a file or directory (if directory, all files are processed recursively)\n")
	fmt.Fprintf(os.Stderr, "-h    print usage message and exit\n")
	flag.VisitAll(func(f *flag.Flag) {
		switch f.Name {
		case "prometheusx.listen-address":
		case "uuid-prefix-file":
		default:
			fmt.Fprintf(os.Stderr, "-%v    %v\n", f.Name, f.Usage)
		}
	})
}

func main() {
	parseCommandLine()
	for _, path := range flag.Args() {
		stat, err := os.Stat(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			continue
		}
		if stat.IsDir() {
			if err := filepath.Walk(path, walk); err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			}
		} else {
			parseAndExamine(path)
		}
	}
	printStats()
}

func parseCommandLine() {
	flag.Usage = usage
	flag.Parse()
	flag.Visit(func(f *flag.Flag) { flagSet[f.Name] = true })
	if *examples {
		printExamples()
		os.Exit(0)
	}
	if flag.NArg() == 0 {
		usage()
		os.Exit(1)
	}
	if flagSet["d"] && flagSet["c"] {
		fmt.Fprintf(os.Stderr, "cannot specify both -c and -d\n")
		os.Exit(1)
	}
	minDuration = math.MaxUint32
}

func walk(path string, info fs.FileInfo, err error) error {
	if err != nil {
		return err
	}
	if info.Mode().IsRegular() {
		parseAndExamine(path)
	}
	return nil
}

// parseAndExamine parses and examines the specified traceroute file.
func parseAndExamine(fileName string) {
	scamper1 := parseFile(fileName)
	if scamper1 == nil {
		return
	}

	// Are we just printing traceroutes that exceeded durations?
	if flagSet["d"] {
		if d := tracerouteDuration(scamper1); d > uint32(*duration) {
			fmt.Printf("%4d %s\n", d, fileName)
		}
		return
	}

	// Are we just printing flow IDs?
	routes := extractSinglePaths(fileName, scamper1)
	if flagSet["c"] {
		return
	}

	printSummary(fileName, scamper1)
	printSinglePaths(routes)
}

// parseFile parses the specified traceroute file which has to be in
// proper ".jsonl" format.
func parseFile(fileName string) *parser.Scamper1 {
	nFilesFound++
	if filepath.Ext(fileName) != ".jsonl" {
		nFilesSkipped++
		return nil
	}
	rawData, err := os.ReadFile(fileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", fileName, err)
		nReadErrors++
		return nil
	}
	mdaParser, err := parser.New("mda")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return nil
	}
	parsedData, err := mdaParser.ParseRawData(rawData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", fileName, err)
		nParseErrors++
		return nil
	}
	var scamper1 parser.Scamper1
	switch p := parsedData.(type) {
	case parser.Scamper1:
		scamper1 = p
	default:
		// This is an internal error because we instantiated a new MDA
		// parser which should return Scamper1 as the concrete type.
		fmt.Fprintf(os.Stderr, "%T: unknown datatype (expected scamper1)", p)
		os.Exit(1)
	}
	nFilesParsed++
	if len(scamper1.Tracelb.Nodes) == 0 {
		nNoTraceroute++
		return nil
	}
	return &scamper1
}

// tracerouteDuration returns the duration of the specified traceroute
// and remembers minimum and maximum durations.
func tracerouteDuration(scamper1 *parser.Scamper1) uint32 {
	d := uint32(scamper1.CycleStop.StopTime - scamper1.CycleStart.StartTime)
	totDuration += uint64(d)
	if d < minDuration {
		minDuration = d
	}
	if d > maxDuration {
		maxDuration = d
	}
	return d
}

// extractSinglePaths extracts single paths from MDA traceroutes.
// Note the following:
//
//   - Not all traceroutes are complete.  That is, not all traceroutes
//     trace all the way to the destination IP address.
//   - Different hops associated with the same flow ID constitute a single path.
//   - The order of hops in a path is determined by the TTL.
//   - Unresponsive hops are marked as an asterisk ("*").
//   - It is possible for a hop to return multiple replies to a probe.
//
// Therefore, for the same flow ID and TTL, there may be zero, one, or multiple
// replies.
func extractSinglePaths(fileName string, scamper1 *parser.Scamper1) map[int64][]Hop {
	routes := make(map[int64][]Hop)
	if len(scamper1.Tracelb.Nodes) == 0 {
		return routes
	}

	// Create a buffer for verbose output.
	vbuf := ""
	vPrintf(&vbuf, "\n%s\n", fileName)
	vPrintf(&vbuf, "Tracelb.Src: %v\n", scamper1.Tracelb.Src)
	vPrintf(&vbuf, "Tracelb.Dst: %v\n", scamper1.Tracelb.Dst)

	completeFlowid := -1
	for i, node := range scamper1.Tracelb.Nodes {
		vPrintf(&vbuf, "Tracelb.Nodes[%d] %s\n", i, node.Addr)
		for j, links := range node.Links {
			for k, link := range links {
				vPrintf(&vbuf, "  Tracelb.Nodes[%d].Links[%d][%d] %s\n", i, j, k, link.Addr)
				for l, probe := range link.Probes {
					vPrintf(&vbuf, "    Tracelb.Nodes[%d].Links[%d][%d].Probes[%d].Flowid: %v\n", i, j, k, l, probe.Flowid)
					flowid := probe.Flowid
					// If this is the first hop in the flow, add Nodes[0].Addr at TTL 1.
					if len(routes[flowid]) == 0 {
						node0 := Hop{addr: scamper1.Tracelb.Nodes[0].Addr, flowid: flowid, ttl: 1}
						routes[flowid] = append(routes[flowid], node0)
					}
					// Add this hop.
					hop := Hop{addr: link.Addr, flowid: flowid, ttl: int(probe.TTL)}
					processProbeReplies(scamper1, probe, &hop)
					// Did this traceroute complete (i.e., reach destination)?
					if hop.addr == scamper1.Tracelb.Dst {
						hop.complete = true
						nCompletes++
						completeFlowid = int(flowid)
					}
					routes[flowid] = append(routes[flowid], hop)
				}
			}
		}
	}

	if *prComplete {
		if completeFlowid == -1 {
			fmt.Printf("%2s %5ds %s\n", "--", tracerouteDuration(scamper1), fileName)
		} else {
			fmt.Printf("%2d %5ds %s\n", completeFlowid, tracerouteDuration(scamper1), fileName)
		}
	}
	if *verbose {
		fmt.Printf("%s", vbuf)
	}
	return routes
}

// processProbeReplies processes the replies to a single probe which
// may have zero, one, or multiple.
func processProbeReplies(scamper1 *parser.Scamper1, probe parser.Probe, hop *Hop) {
	replies := probe.Replies
	if len(replies) > 1 {
		fmt.Printf(">>> len(replies)=%d\n", len(replies))
	}
	tx := sinceTracelbStart(scamper1, probe.Tx.Sec*1000000+probe.Tx.Usec)
	if len(replies) == 0 {
		hop.tx = []int64{tx}
		hop.rx = []int64{-1}
		hop.rtt = []float64{-1.0}
	} else {
		for n := 0; n < len(replies); n++ {
			hop.tx = append(hop.tx, tx)
			hop.rx = append(hop.rx, sinceTracelbStart(scamper1, replies[n].Rx.Sec*1000000+replies[n].Rx.Usec))
			hop.rtt = append(hop.rtt, replies[n].RTT)
		}
	}
}

// sinceTracelbStart returns how much time in milliseconds has elapsed
// for the given time t since tracelb started.
func sinceTracelbStart(scamper1 *parser.Scamper1, t int64) int64 {
	if t == 0 {
		return 0
	}
	return (t - (scamper1.Tracelb.Start.Sec*1000000 + scamper1.Tracelb.Start.Usec)) / 1000
}

// vPrintf adds to the buffer vbuf if verbose mode is enabled.
func vPrintf(vbuf *string, format string, args ...interface{}) {
	if *verbose {
		*vbuf += fmt.Sprintf(format, args...)
	}
}

// printSinglePaths prints single-path traceroutes.
// When showing single-paths, only complete paths (if any) are printed.
// If you need to see all paths, use the "-v" flag to enable the verbose
// mode.
func printSinglePaths(routes map[int64][]Hop) {
	if len(routes) == 0 {
		return
	}
	// Sort the flow IDs so we always print in ascending order.
	flowids := make([]int, 0)
	for _, hops := range routes {
		flowids = append(flowids, int(hops[0].flowid))
	}
	sort.Ints(flowids)
	for _, f := range flowids {
		flowid := int64(f)
		// If verbose is true, we print all flow ID paths regardless
		// of whether they were complete or not.  Otherwise, check
		// to see if any flow IDs are complete for this traceroute
		// to be printed.
		if *verbose {
			fmt.Printf("flowid: %d\n", flowid)
			printHops(routes[flowid])
		} else {
			for _, hop := range routes[int64(flowid)] {
				if hop.complete {
					fmt.Printf("flowid: %d\n", flowid)
					printHops(routes[flowid])
					break
				}
			}
		}
	}
}

// printHops prints all the hops that are associated with each flow ID.
func printHops(hops []Hop) {
	fmt.Printf("%3s  %8s %8s %10s  %s\n", "TTL", "TX(ms)", "RX(ms)", "RTT(ms)", "IP address")

	prevTTL := 1
	var totRTT float64
	for _, hop := range hops {
		// Sanity check.
		if hop.ttl == 0 {
			panic("ttl 0")
		}

		// Print "*" for the missing TTLs because the
		// corresponding hops were unresponsive.
		for ttl := prevTTL; ttl < hop.ttl; ttl++ {
			fmt.Printf("%3d  %8s %8s %10s  %s\n", ttl, "*", "*", "*", "*")
		}
		prevTTL = hop.ttl + 1

		if hop.ttl == 1 {
			fmt.Printf("%3d  %8s %8s %10s  %s", hop.ttl, "N/A", "N/A", "N/A", hop.addr)
		} else {
			for n := 0; n < len(hop.rtt); n++ {
				if hop.rtt[n] == -1.0 { // no replies
					fmt.Printf("%3d  %8s %8s %10s  %s", hop.ttl, "*", "*", "*", hop.addr)
				} else {
					fmt.Printf("%3d  %8d %8d %10.3f  %s", hop.ttl, hop.tx[n], hop.rx[n], hop.rtt[n], hop.addr)
					totRTT += hop.rtt[n]
				}
				// If not in verbose mode, only print one reply.
				if !*verbose {
					break
				}
			}
		}
		if hop.complete {
			fmt.Printf("  <=== destination")
		}
		fmt.Println()
	}
	fmt.Printf("%3s  %8s %8s %10.3f\n", " ", " ", " ", totRTT)
}

// printSummary prints a summary of the specified traceroute.
func printSummary(fileName string, scamper1 *parser.Scamper1) {
	fmt.Printf("\nfile: %s\n", fileName)
	fmt.Printf("src: %s\n", scamper1.Tracelb.Src)
	fmt.Printf("dst: %s\n", scamper1.Tracelb.Dst)
	scamperStart := int64(scamper1.CycleStart.StartTime)
	tracelbStart := scamper1.Tracelb.Start.Sec
	scamperStop := int64(scamper1.CycleStop.StopTime)
	fmt.Printf("scamper start: %d\n", scamperStart)
	fmt.Printf("tracelb start: %d (%d seconds after scamper start)\n", tracelbStart, tracelbStart-scamperStart)
	fmt.Printf("scamper stop:  %d (%d seconds after scamper start)\n", scamperStop, scamperStop-scamperStart)
}

// printStats prints statistics of all files processed.
func printStats() {
	if nFilesFound > 1 {
		fmt.Println()
		fmt.Printf("files found:                     %8d\n", nFilesFound)
		fmt.Printf("files skipped (not .jsonl):      %8d\n", nFilesSkipped)
		fmt.Printf("files that could not be read:    %8d\n", nReadErrors)
		fmt.Printf("files that could not be parsed:  %8d\n", nParseErrors)
		fmt.Printf("files successfully parsed:       %8d\n", nFilesParsed)
		fmt.Printf("files with no traceroute data:   %8d\n", nNoTraceroute)
		if !flagSet["d"] {
			fmt.Printf("files with complete traceroutes: %8d ", nCompletes)
			if nFilesParsed != 0 {
				fmt.Printf(" (%.f%%)", float32((nCompletes*100.0)/nFilesParsed))
			}
		}
		fmt.Println()
	}
	if flagSet["d"] && nFilesParsed > 0 {
		fmt.Printf("minimum duration:                %8d seconds\n", minDuration)
		fmt.Printf("maximum duration:                %8d seconds\n", maxDuration)
		if nFilesParsed != 0 {
			fmt.Printf("average duration:                %8d seconds\n", totDuration/uint64(nFilesParsed))
		}
	}
}

// printExample prints one example command line for different use cases
// of this tool:
// 1. Extract single-path traceroutes.
// 2. List traceroutes that took longer than a specified duration.
// 3. List complete and incomplete traceroutes.
func printExamples() {
	fmt.Printf(`Examples:
# Extract and print a single-path traceroute (if it exists) from a traceroute file
$ trex /traceroutes/2022/04/01/20220401T001905Z_ndt-qqvlt_1647967485_000000000009379D.jsonl

file: /traceroutes/2022/04/01/20220401T001905Z_ndt-qqvlt_1647967485_000000000009379D.jsonl
src: 209.170.110.216
dst: 199.19.248.6
scamper start: 1648772345
tracelb start: 1648772345 (0 seconds after scamper start)
scamper stop:  1648772346 (1 seconds after scamper start)
flowid: 1
TTL    TX(ms)   RX(ms)    RTT(ms)  IP address
  1       N/A      N/A      0.000  209.170.110.193
  2       150      151      0.653  213.248.100.57
  3      1055     1062      7.244  199.19.248.6  <=== destination
                            7.897

The TX and RX columns are elapsed transmit and receive times since the tracelb
command was started.


# Same command as above but enable the verbose mode (useful for debugging).
$ trex -v /traceroutes/2022/04/01/20220401T001905Z_ndt-qqvlt_1647967485_000000000009379D.jsonl

/traceroutes/2022/04/01/20220401T001905Z_ndt-qqvlt_1647967485_000000000009379D.jsonl
Tracelb.Src: 209.170.110.216
Tracelb.Dst: 199.19.248.6
Tracelb.Nodes[0] 209.170.110.193
  Tracelb.Nodes[0].Links[0][0] 213.248.100.57
    Tracelb.Nodes[0].Links[0][0].Probes[0].Flowid: 1
    Tracelb.Nodes[0].Links[0][0].Probes[1].Flowid: 2
    Tracelb.Nodes[0].Links[0][0].Probes[2].Flowid: 3
    Tracelb.Nodes[0].Links[0][0].Probes[3].Flowid: 4
    Tracelb.Nodes[0].Links[0][0].Probes[4].Flowid: 5
    Tracelb.Nodes[0].Links[0][0].Probes[5].Flowid: 6
Tracelb.Nodes[1] 213.248.100.57
  Tracelb.Nodes[1].Links[0][0] 199.19.248.6
    Tracelb.Nodes[1].Links[0][0].Probes[0].Flowid: 1

file: /traceroutes/2022/04/01/20220401T001905Z_ndt-qqvlt_1647967485_000000000009379D.jsonl
src: 209.170.110.216
dst: 199.19.248.6
scamper start: 1648772345
tracelb start: 1648772345 (0 seconds after scamper start)
scamper stop:  1648772346 (1 seconds after scamper start)
flowid: 1
TTL    TX(ms)   RX(ms)    RTT(ms)  IP address
  1       N/A      N/A      0.000  209.170.110.193
  2       150      151      0.653  213.248.100.57
  3      1055     1062      7.244  199.19.248.6  <=== destination
                            7.897
flowid: 2
TTL    TX(ms)   RX(ms)    RTT(ms)  IP address
  1       N/A      N/A      0.000  209.170.110.193
  2       301      302      0.644  213.248.100.57
                            0.644
flowid: 3
TTL    TX(ms)   RX(ms)    RTT(ms)  IP address
  1       N/A      N/A      0.000  209.170.110.193
  2       452      453      0.707  213.248.100.57
                            0.707
flowid: 4
TTL    TX(ms)   RX(ms)    RTT(ms)  IP address
  1       N/A      N/A      0.000  209.170.110.193
  2       603      604      0.608  213.248.100.57
                            0.608
flowid: 5
TTL    TX(ms)   RX(ms)    RTT(ms)  IP address
  1       N/A      N/A      0.000  209.170.110.193
  2       754      754      0.621  213.248.100.57
                            0.621
flowid: 6
TTL    TX(ms)   RX(ms)    RTT(ms)  IP address
  1       N/A      N/A      0.000  209.170.110.193
  2       904      905      0.673  213.248.100.57
                            0.673


# Print all traceroute files in a directory hierarchy that took longer than 5 minutes
$ trex -d 300 /traceroutes/2021
 428 /traceroutes/2021/10/01/20211001T000053Z_ndt-292jb_1632518393_00000000000516D4.jsonl
 386 /traceroutes/2021/10/01/20211001T000151Z_ndt-292jb_1632518393_000000000005160D.jsonl
...

files found:                          425
files skipped (not .jsonl):             0
files that could not be read:           0
files that could not be parsed:         0
files successfully parsed:            425
files with no traceroute data:          0

minimum duration:                       4 seconds
maximum duration:                     456 seconds
average duration:                     220 seconds


# Print flow ID of complete traceroutes ("--" if incomplete) in a directory hierarchy
$ ./trex -c /traceroutes/2021
 1 /traceroutes/2021/10/01/20211001T000014Z_ndt-292jb_1632518393_00000000000516C8.jsonl
 1 /traceroutes/2021/10/01/20211001T000015Z_ndt-292jb_1632518393_00000000000516C9.jsonl
-- /traceroutes/2021/10/01/20211001T000023Z_ndt-292jb_1632518393_00000000000516C4.jsonl
...

files found:                          425
files skipped (not .jsonl):             0
files that could not be read:           0
files that could not be parsed:         0
files successfully parsed:            425
files with no traceroute data:          0
files with complete traceroutes:      149  (35%%)
`)
}
