package main

import (
	"flag"
	"fmt"
	"io/fs"
	"io/ioutil"
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
	flowid   int
	addr     string
	ttl      int
	rtt      float64 // response time - transmit time in milliseconds
	complete bool    // route is complete and reaches destination
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

func parseAndExamine(fileName string) {
	scamper1 := parseFile(fileName)
	if scamper1 == nil {
		return
	}

	// Are we just printing traceroutes that exceeded durations?
	if flagSet["d"] {
		if d := computeDuration(scamper1); d > uint32(*duration) {
			fmt.Printf("%4d %s\n", d, fileName)
		}
		return
	}

	// Are we just printing flow IDs?
	routes := extractSinglePaths(fileName, scamper1)
	if len(routes) == 0 || *prComplete {
		return
	}

	printSinglePaths(fileName, routes)
}

func computeDuration(scamper1 *parser.Scamper1) uint32 {
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

func parseFile(fileName string) *parser.Scamper1 {
	nFilesFound++
	if filepath.Ext(fileName) != ".jsonl" {
		nFilesSkipped++
		return nil
	}
	rawData, err := ioutil.ReadFile(fileName)
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
		fmt.Fprintf(os.Stderr, "%v\n", err)
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

// extractSinglePaths extracts single paths from MDA traceroutes.
// - Not all traceroutes are complete.  That is, not all traceroutes
//   trace all the way to the destination IP address.
// - Different hops associated with the same flow ID constitute a single path.
// - The order of hops in a path is determined by the TTL.
// - Unresponsive hops are marked as an asterisk ("*").
// - It is possible for a hop to return multiple replies to a probe.
//   Therefore, for the same flow ID and TTL, there may be zero, one, or more
//   than one replies.
func extractSinglePaths(fileName string, scamper1 *parser.Scamper1) map[int][]Hop {
	routes := make(map[int][]Hop)
	complete := false
	if len(scamper1.Tracelb.Nodes) == 0 {
		return routes
	}
	vbuf := fmt.Sprintf("\n%s\n\n", fileName)
	src := scamper1.Tracelb.Src
	dst := scamper1.Tracelb.Dst
	node0 := scamper1.Tracelb.Nodes[0].Addr
	for i, node := range scamper1.Tracelb.Nodes {
		vbuf += fmt.Sprintf("Tracelb.Nodes[%d] %s\n", i, node.Addr)
		for j, links := range node.Links {
			for k, link := range links {
				addr := link.Addr
				vbuf += fmt.Sprintf("  Tracelb.Nodes[%d].Links[%d][%d] %s\n", i, j, k, addr)
				for l, probe := range link.Probes {
					flowid := int(probe.Flowid)
					vbuf += fmt.Sprintf("    Tracelb.Nodes[%d].Links[%d][%d].Probes[%d].Flowid: %v\n", i, j, k, l, flowid)
					// If this is the first hop to add for this flowid, add src and node0.
					if len(routes[flowid]) == 0 {
						routes[flowid] = append(routes[flowid],
							Hop{flowid: flowid, addr: src},
							Hop{flowid: flowid, addr: node0, ttl: 1},
						)
					}
					nReplies := len(probe.Replies)
					var m int
					if nReplies == 0 {
						m = 1
					} else {
						m = nReplies
					}
					for n := 0; n < m; n++ {
						var rtt float64
						if nReplies == 0 {
							rtt = -1.0 // no replies
						} else {
							rtt = probe.Replies[0].RTT
						}
						hop := Hop{flowid: flowid, addr: addr, ttl: int(probe.TTL), rtt: rtt}
						// Did this traceroute complete (i.e., reach destination)?
						if hop.addr == dst {
							hop.complete = true
							complete = true
							if *prComplete {
								fmt.Printf("%2d %s\n", flowid, fileName)
							}
						}
						routes[flowid] = append(routes[flowid], hop)
					}
				}
			}
		}
	}
	if complete {
		nCompletes++
	} else if *prComplete {
		fmt.Printf("-- %s\n", fileName)
	}
	if *verbose {
		fmt.Printf("%s", vbuf)
	}
	return routes
}

// printSinglePaths prints single-path traceroutes.
// When showing single-paths, only complete paths (if any) are printed.
// If you need to see all paths, use the "-v" flag to enable the verbose
// mode.
func printSinglePaths(fileName string, routes map[int][]Hop) {
	// Sort the flow IDs so we always print in ascending order.
	flowids := make([]int, 0)
	for _, hops := range routes {
		flowids = append(flowids, hops[0].flowid)
	}
	sort.Ints(flowids)
	for _, flowid := range flowids {
		// If verbose is true, we print all flow ID paths regardless
		// of whether they were complete or not.  Otherwise, check
		// to see if any flow IDs are complete for this traceroute
		// to be printed.
		print := *verbose
		if !*verbose {
			for _, hop := range routes[flowid] {
				if hop.complete {
					print = true
					break
				}
			}
		}
		if !print {
			continue
		}
		fmt.Printf("\n%s\nflowid: %d\n", fileName, flowid)
		fmt.Printf("TTL     RTT(ms) IP address\n")
		// In case there are multiple replies from a
		// hop for the same TTL, we don't want to print
		// all of them.
		hopTTL := make(map[int]bool)
		prevTTL := 0
		for _, hop := range routes[flowid] {
			// Print "*" for the missing TTLs because the
			// corresponding hops were unresponsive.
			for ttl := prevTTL; ttl < hop.ttl; ttl++ {
				if !hopTTL[ttl] || *verbose {
					fmt.Printf("%3d  %10s *\n", ttl, "*")
					hopTTL[ttl] = true
				}
			}
			prevTTL = hop.ttl + 1
			if !hopTTL[hop.ttl] || *verbose {
				if hop.rtt == -1.0 { // no replies
					fmt.Printf("%3d  %10s %s", hop.ttl, "*", hop.addr)
				} else {
					fmt.Printf("%3d  %10.3f %s", hop.ttl, hop.rtt, hop.addr)
				}
				if hop.complete {
					fmt.Printf("  <=== destination")
				}
				fmt.Println()
				hopTTL[hop.ttl] = true
			}
		}
	}
}

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
//   1. Extract single-path traceroutes.
//   2. List traceroutes that took longer than a specified duration.
//   3. List complete and incomplete traceroutes.
func printExamples() {
	fmt.Printf(`Examples:
# Extract and print a single-path traceroute (if it exists) from a traceroute file
$ ./trex ~/traceroutes/2021/10/01/20211001T002556Z_ndt-292jb_1632518393_0000000000051A0C.jsonl

2021/10/01/20211001T002556Z_ndt-292jb_1632518393_0000000000051A0C.jsonl
flowid: 1
TTL     RTT(ms) IP address
  0       0.000 2001:500d:200:3::139
  1       0.000 2001:500d:200:3::1
  2       6.510 2001:500d:100::2
  3       1.197 2001:4860:0:23::2
  4      43.398 2001:4860::9:4001:2751
  5      34.590 2001:4860::c:4000:d9ab
  6      33.923 2001:4860::c:4000:dd7a
  7      34.548 2607:f8b0:e000:8000::5
  8           * *
  9      33.530 2a00:1450:4009:817::2010  <=== destination

# Print all traceroute files in a directory hierarchy that took longer than 5 minutes
$ ./trex -d 300 ~/traceroutes/2021
 428 2021/10/01/20211001T000053Z_ndt-292jb_1632518393_00000000000516D4.jsonl
 386 2021/10/01/20211001T000151Z_ndt-292jb_1632518393_000000000005160D.jsonl
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
$ ./trex -c 2021    
 1 2021/10/01/20211001T000014Z_ndt-292jb_1632518393_00000000000516C8.jsonl
 1 2021/10/01/20211001T000015Z_ndt-292jb_1632518393_00000000000516C9.jsonl
-- 2021/10/01/20211001T000023Z_ndt-292jb_1632518393_00000000000516C4.jsonl
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
