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
	fmt.Println("Example usages are provided at the following URL:")
	fmt.Println("https://github.com/m-lab/traceroute-caller/blob/master/README.md#traceroute-examiner-tool-trex")
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
					// Add this hop.  Note that the number of times this hop is
					// added to the map is equal to the number of the probes it
					// has transmitted (usually one, but sometimes more than one).
					hop := Hop{addr: link.Addr, flowid: flowid, ttl: int(probe.TTL)}
					processProbe(scamper1, probe, &hop)
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

// processProbe processes a single probe which may have zero, one,
// or multiple replies.
func processProbe(scamper1 *parser.Scamper1, probe parser.Probe, hop *Hop) {
	replies := probe.Replies
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
	for i, hop := range hops {
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

		// If not in verbose mode, print this hop only once
		// even if it sent multiple probes.
		if !*verbose && i > 0 && hop.ttl == hops[i-1].ttl {
			continue
		}

		s := ""
		if hop.complete {
			s = "  <=== destination"
		}
		if hop.ttl == 1 {
			fmt.Printf("%3d  %8s %8s %10s  %s%s\n", hop.ttl, "N/A", "N/A", "N/A", hop.addr, s)
		} else {
			for n := 0; n < len(hop.rtt); n++ {
				if hop.rtt[n] == -1.0 { // no replies
					fmt.Printf("%3d  %8s %8s %10s  %s%s", hop.ttl, "*", "*", "*", hop.addr, s)
				} else {
					fmt.Printf("%3d  %8d %8d %10.3f  %s%s", hop.ttl, hop.tx[n], hop.rx[n], hop.rtt[n], hop.addr, s)
				}
				// If not in verbose mode, print only one reply.
				if !*verbose {
					if len(hop.rtt) > 1 {
						fmt.Printf("  <=== %d more probe replies\n", len(hop.rtt)-1)
						break
					}
				}
				fmt.Println()
			}
		}
		// If not in verbose mode, stop after reaching destination.
		if !*verbose && hop.complete {
			break
		}
	}
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
