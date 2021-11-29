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
	"github.com/m-lab/traceroute-caller/tracer"
	"github.com/m-lab/traceroute-caller/triggertrace"
	"github.com/m-lab/uuid-annotator/ipservice"
)

var (
	scamperBin          = flag.String("scamper.bin", "scamper", "The path to the scamper binary.")
	scamperTimeout      = flag.Duration("scamper.timeout", 900*time.Second, "How long to wait to complete a scamper trace.")
	scamperPTR          = flag.Bool("scamper.tracelb-ptr", true, "Look up DNS pointer records for IP addresses.")
	scamperWaitProbe    = flag.Int("scamper.tracelb-W", 25, "How long to wait between probes in 1/100ths of seconds (min 15, max 200).")
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
	errNewHandler  = errors.New("failed to create a triggertrace handler")
)

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

	// The triggertrace package needs to know which trace tool to
	// use for running traceroutes, how long to keep traceroute results
	// in the cache, and which service to use for annotating the hops.
	scamper := &tracer.Scamper{
		Binary:           *scamperBin,
		OutputPath:       *tracerouteOutput,
		ScamperTimeout:   *scamperTimeout,
		TracelbPTR:       *scamperPTR,
		TracelbWaitProbe: *scamperWaitProbe,
	}
	ipcCfg := ipcache.Config{
		EntryTimeout: *ipcEntryTimeout,
		ScanPeriod:   *ipcScanPeriod,
	}
	haCfg := hopannotation.Config{
		AnnotatorClient: ipservice.NewClient(*ipservice.SocketFilename),
		OutputPath:      *hopAnnotationOutput,
	}
	traceHandler, err := triggertrace.NewHandler(ctx, scamper, ipcCfg, haCfg)
	if err != nil {
		logFatal(fmt.Errorf("%v: %w", errNewHandler, err))
	}
	eventsocket.MustRun(ctx, *eventsocket.Filename, traceHandler)
}
