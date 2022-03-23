package main

import (
	"flag"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"

	"github.com/m-lab/traceroute-caller/parser"
)

var (
	prComplete = flag.Bool("c", false, "print flow IDs and file names of traceroutes that completed (\"--\" for incomplete traceroutes)")
	duration   = flag.Int("d", -1, "print times and file names of traceroutes that took more than the specified duration")
	examples   = flag.Bool("e", false, "print examples how to use this tool and exit")
	verbose    = flag.Bool("v", false, "enable verbose mode (mostly for debugging)")

	// Statistics printed before exiting.
	nFilesFound   int   // files found
	nFilesSkipped int   // files skipped (not .jsonl)
	nReadErrors   int   // files that couldn't be read
	nParseErrors  int   // files that couldn't be parsed
	nFilesParsed  int   // files successfully parsed
	nNoTraceroute int   // files with no traceroute data
	nCompletes    int   // files with complete traceroutes (i.e., traceroute reaches destination)
	minDuration   int   // minimum traceroute duration
	maxDuration   int   // maximum traceroute duration
	totDuration   int64 // total duration of all traceroutes
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
			err = filepath.Walk(path, walk)
		} else {
			parseAndExamine(path)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
		}
	}
	printStats()
}

func parseCommandLine() {
	flagSet := make(map[string]bool)
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
	if flagSet["d"] {
		if flagSet["c"] {
			fmt.Fprintf(os.Stderr, "cannot specify both -c and -d\n")
			os.Exit(1)
		}
		if *duration < 0 {
			fmt.Fprintf(os.Stderr, "%d: invalid duration value\n", *duration)
			os.Exit(1)
		}
	}
	minDuration = 1000000
}

func walk(path string, info fs.FileInfo, err error) error {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%q: %v\n", path, err)
		return err
	}
	if info.Mode().IsRegular() {
		if filepath.Ext(path) == ".jsonl" {
			parseAndExamine(path)
		} else {
			nFilesSkipped++
		}
	}
	return nil
}

func parseAndExamine(fileName string) {
	scamper1 := parseFile(fileName)
	if scamper1 == nil {
		return
	}

	// Are we just printing traceroutes that exceeded durations?
	if *duration >= 0 {
		if d := computeDuration(scamper1); d > *duration {
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

func computeDuration(scamper1 *parser.Scamper1) int {
	d := int(scamper1.CycleStop.StopTime - scamper1.CycleStart.StartTime)
	totDuration += int64(d)
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
	newParser, err := parser.New("mda")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return nil
	}
	parsedData, err := newParser.ParseRawData(rawData)
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
		fmt.Fprintf(os.Stderr, "%T: unknown datatype (expected scamper1)", p)
		return nil
	}
	nFilesParsed++
	if len(scamper1.Tracelb.Nodes) == 0 {
		nNoTraceroute++
		return nil
	}
	return &scamper1
}

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
		if *duration < 0 {
			fmt.Printf("files with complete traceroutes: %8d ", nCompletes)
			if nFilesParsed != 0 {
				fmt.Printf(" (%.f%%)", float32((nCompletes*100.0)/nFilesParsed))
			}
		}
		fmt.Println()
	}
	if *duration >= 0 && nFilesParsed > 0 {
		fmt.Printf("minimum duration:                %8d seconds\n", minDuration)
		fmt.Printf("maximum duration:                %8d seconds\n", maxDuration)
		if nFilesParsed != 0 {
			fmt.Printf("average duration:                %8d seconds\n", totDuration/int64(nFilesParsed))
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
