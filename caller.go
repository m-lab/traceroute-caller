// traceroute-caller is a wrapper around scamper, a tool that actively
// probes the Internet in order to analyze topology and performance.
// For details, visit https://www.caida.org/catalog/software/scamper.
//
// traceroute-caller uses the tcp-info/eventsocket package to listen for
// open and close connection events, and runs a traceroute measurement
// on closed connections.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"sync"
	"time"

	"github.com/m-lab/traceroute-caller/connection"
	"github.com/m-lab/traceroute-caller/connectionlistener"
	"github.com/m-lab/traceroute-caller/hopannotation"
	"github.com/m-lab/traceroute-caller/ipcache"
	"github.com/m-lab/traceroute-caller/tracer"

	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/prometheusx"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/eventsocket"
	"github.com/m-lab/uuid-annotator/ipservice"
)

var (
	// TODO(SaiedKazemi): scamper and its commands (e.g., tracelb)
	//     support a large number of flags.  Instead of adding
	//     these flags one by one to traceroute-caller flags, it
	//     will be much better to have traceroute-caller read a
	//     configuration file in textproto format that would support
	//     all scamper and its command flags.
	scamperBin          = flag.String("scamper.bin", "scamper", "The path to the scamper binary.")
	scattachBin         = flag.String("scamper.sc_attach", "sc_attach", "The path to the sc_attach binary.")
	scwarts2jsonBin     = flag.String("scamper.sc_warts2json", "sc_warts2json", "The path to the sc_warts2json binary.")
	scamperCtrlSocket   = flag.String("scamper.unixsocket", "/tmp/scamperctrl", "The name of the UNIX-domain socket that the scamper daemon should listen on.")
	scamperTimeout      = flag.Duration("scamper.timeout", 900*time.Second, "How long to wait to complete a scamper trace.")
	scamperPTR          = flag.Bool("scamper.tracelb-ptr", true, "Look up DNS pointer records for IP addresses.")
	scamperWaitProbe    = flag.Int("scamper.tracelb-W", 25, "How long to wait between probes in 1/100ths of seconds (min 15, max 200).")
	tracerouteOutput    = flag.String("traceroute-output", "/var/spool/scamper", "The path to store traceroute output.")
	hopAnnotationOutput = flag.String("hopannotation-output", "/var/spool/hopannotation1", "The path to store hop annotations.")
	tracerType          = flagx.Enum{
		Options: []string{"scamper", "scamper-daemon"},
		Value:   "scamper",
	}

	// Variables to aid in testing of main()
	ctx, cancel = context.WithCancel(context.Background())
	logFatal    = log.Fatal
)

func init() {
	flag.Var(&tracerType, "tracetool", "Choose whether scamper or scamper-daemon should be used.")
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.Parse()
	rtx.Must(flagx.ArgsFromEnv(flag.CommandLine), "failed to get args from environment")
	if *eventsocket.Filename == "" {
		logFatal("tcpinfo.eventsocket was set to \"\"")
	}
	rtx.Must(os.MkdirAll(*tracerouteOutput, 0777), "failed to create directory for traceroute results")
	rtx.Must(os.MkdirAll(*hopAnnotationOutput, 0777), "failed to create directory for hop annotation results")

	defer cancel()
	wg := sync.WaitGroup{}

	promSrv := prometheusx.MustServeMetrics()
	defer func() {
		if err := promSrv.Shutdown(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("failed to shut down Prometheus server (error: %v)", err)
		}
	}()

	scamper := &tracer.Scamper{
		Binary:           *scamperBin,
		OutputPath:       *tracerouteOutput,
		ScamperTimeout:   *scamperTimeout,
		TracelbPTR:       *scamperPTR,
		TracelbWaitProbe: *scamperWaitProbe,
	}
	scamperDaemon := &tracer.ScamperDaemon{
		Scamper:          scamper,
		AttachBinary:     *scattachBin,
		Warts2JSONBinary: *scwarts2jsonBin,
		ControlSocket:    *scamperCtrlSocket,
	}

	// Set up the ipCache depending on the trace method requested.
	var ipCache *ipcache.RecentIPCache
	switch tracerType.Value {
	case "scamper":
		ipCache = ipcache.New(ctx, scamper, *ipcache.IPCacheTimeout, *ipcache.IPCacheUpdatePeriod)
	case "scamper-daemon":
		ipCache = ipcache.New(ctx, scamperDaemon, *ipcache.IPCacheTimeout, *ipcache.IPCacheUpdatePeriod)
		wg.Add(1)
		go func() {
			scamperDaemon.MustStart(ctx)
			// When the scamper daemon dies, cancel main() and exit.
			cancel()
			wg.Done()
		}()
	}

	localIPs, err := connection.NewLocalRemoteIPs()
	rtx.Must(err, "failed to discover local IPs")
	ipserviceClient := ipservice.NewClient(*ipservice.SocketFilename)
	hopAnnotator := hopannotation.New(ctx, ipserviceClient, *hopAnnotationOutput)
	connListener := connectionlistener.New(localIPs, ipCache, hopAnnotator)
	eventsocket.MustRun(ctx, *eventsocket.Filename, connListener)
	cancel()
	wg.Wait()
}
