// traceroute-caller is a wrapper around scamper, a tool that actively
// probes the Internet in order to analyze topology and performance.
// For details, visit https://www.caida.org/catalog/software/scamper.
//
// traceroute-caller uses the tcp-info/eventsocket package to be notified
// of open and close connection events. A close connection event triggers
// a traceroute run to that destination.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/prometheusx"
	"github.com/m-lab/tcp-info/eventsocket"
	"github.com/m-lab/traceroute-caller/hopannotation"
	"github.com/m-lab/traceroute-caller/ipcache"
	"github.com/m-lab/traceroute-caller/parser"
	"github.com/m-lab/traceroute-caller/tracer"
	"github.com/m-lab/traceroute-caller/triggertrace"
	"github.com/m-lab/uuid-annotator/ipservice"
)

var (
	scamperBin       = flag.String("scamper.bin", "/usr/local/bin/scamper", "The path to the scamper binary.")
	scamperTimeout   = flag.Duration("scamper.timeout", 900*time.Second, "How long to wait for scamper to complete a traceroute.")
	scamperTraceType = flagx.Enum{
		Options: []string{"mda"}, // "regular" will be added soon
		Value:   "mda",
	}
	scamperTracelbPTR   = flag.Bool("scamper.tracelb-ptr", true, "mda traceroute option: Look up DNS pointer records for IP addresses.")
	scamperTracelbW     = flag.Int("scamper.tracelb-W", 25, "mda traceroute option: Wait time between probes in 1/100ths of seconds (min 15, max 200).")
	tracerouteOutput    = flag.String("traceroute-output", "/var/spool/scamper1", "The path to store traceroute output.")
	hopAnnotationOutput = flag.String("hopannotation-output", "/var/spool/hopannotation1", "The path to store hop annotation output.")
	// Keeping IP cache flags capitalized for backward compatibility.
	ipcEntryTimeout = flag.Duration("IPCacheTimeout", 10*time.Minute, "Timeout duration in seconds for an IP cache entry.")
	ipcScanPeriod   = flag.Duration("IPCacheUpdatePeriod", 1*time.Minute, "IP cache scanning period in seconds.")

	// Variables to aid in testing of main().
	ctx, cancel    = context.WithCancel(context.Background())
	logFatal       = log.Fatal
	errEnvArgs     = errors.New("failed to get args from environment")
	errEventSocket = errors.New("tcpinfo.eventsocket value was empty")
	errScamper     = errors.New("failed to configure scamper")
	errNewHandler  = errors.New("failed to create a triggertrace handler")
)

func init() {
	flag.Var(&scamperTraceType, "scamper.trace-type", "Specify the type of traceroute to run (currently only mda).")
}

func main() {
	defer cancel()
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.Parse()
	if err := flagx.ArgsFromEnv(flag.CommandLine); err != nil {
		logFatal(fmt.Errorf("%v: %w", errEnvArgs, err))
	}
	if *eventsocket.Filename == "" {
		logFatal(errEventSocket)
	}

	promSrv := prometheusx.MustServeMetrics()
	defer func() {
		if err := promSrv.Shutdown(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("failed to shut down Prometheus server (error: %v)", err)
		}
	}()

	// The triggertrace package needs the following:
	//   - A traceroute tool for running traceroutes.
	//   - A traceroute cache to keep traceroute results.
	//   - A parser to parse traceroutes.
	//   - A hop annotator for annotating IP addresses.
	// The traceroute tool (scamper).
	scamper := &tracer.Scamper{
		Binary:           *scamperBin,
		OutputPath:       *tracerouteOutput,
		Timeout:          *scamperTimeout,
		TraceType:        scamperTraceType.Value,
		TracelbPTR:       *scamperTracelbPTR,
		TracelbWaitProbe: *scamperTracelbW,
	}
	if err := scamper.Validate(); err != nil {
		logFatal(fmt.Errorf("%v: %w", errScamper, err))
	}
	// The traceroute cache.
	// TODO(SaiedKazemi): The name ipcache (in its various forms)
	// should be changed to trcache because the cache holds traceroutes
	// values -- IP is simply the key.  Anyway, IP will go away when IP
	// annonymization is implemented.
	ipcCfg := ipcache.Config{
		EntryTimeout: *ipcEntryTimeout,
		ScanPeriod:   *ipcScanPeriod,
	}
	// The traceroute parser.
	newParser, err := parser.New(scamperTraceType.Value)
	if err != nil {
		logFatal(err)
	}
	// The hop annotator.
	haCfg := hopannotation.Config{
		AnnotatorClient: ipservice.NewClient(*ipservice.SocketFilename),
		OutputPath:      *hopAnnotationOutput,
	}
	traceHandler, err := triggertrace.NewHandler(ctx, scamper, ipcCfg, newParser, haCfg)
	if err != nil {
		logFatal(fmt.Errorf("%v: %w", errNewHandler, err))
	}
	eventsocket.MustRun(ctx, *eventsocket.Filename, traceHandler)
}
