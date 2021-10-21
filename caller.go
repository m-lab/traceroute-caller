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
	"log"

	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/prometheusx"
	"github.com/m-lab/tcp-info/eventsocket"
	"github.com/m-lab/traceroute-caller/tracer"
	"github.com/m-lab/traceroute-caller/triggertrace"
)

var (
	// Variables to aid in testing of main().
	ctx      context.Context
	cancel   context.CancelFunc
	logFatal = log.Fatal
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.Parse()
	if err := flagx.ArgsFromEnv(flag.CommandLine); err != nil {
		logFatal("failed to get args from environment (error: %v)", err)
	}
	if *eventsocket.Filename == "" {
		logFatal("tcpinfo.eventsocket value was empty")
	}

	if ctx == nil {
		ctx, cancel = context.WithCancel(context.Background())
	}
	if cancel != nil {
		defer cancel()
	}
	promSrv := prometheusx.MustServeMetrics()
	defer func() {
		if err := promSrv.Shutdown(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("failed to shut down Prometheus server (error: %v)", err)
		}
	}()

	scamper := &tracer.Scamper{
		Binary:           *tracer.ScamperBin,
		OutputPath:       *tracer.TracerouteOutput,
		ScamperTimeout:   *tracer.ScamperTimeout,
		TracelbPTR:       *tracer.ScamperPTR,
		TracelbWaitProbe: *tracer.ScamperWaitProbe,
	}
	traceHandler, err := triggertrace.NewHandler(ctx, scamper)
	if err != nil {
		logFatal("failed to create a new triggertrace handler (error: %v)", err)
	}
	eventsocket.MustRun(ctx, *eventsocket.Filename, traceHandler)
}
