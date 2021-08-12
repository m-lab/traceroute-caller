// traceroute-caller is a wrapper around the
// `scamper` commands and can be invoked in two different poll and
// listen modes:
//
//   - Poll mode uses the `connectionpoller` package to get a complete list
//     of all connections by executing `/bin/ss -e -n` every 5 seconds
//     and running a traceroute on all closed connections.  This mode is
//     mostly for local test and debugging purposes as it doesn't require
//     any services such as `tcp-info` or `uuid-annotator`.
//
//   - Listen mode uses the `tcp-info/eventsocket` package to listen for
//     open and close connection events, and runs a traceroute measurement
//     on closed connections.
//
// traceroute-caller on M-Lab servers always runs in the listen mode.
// To see all available flags:
//
//   $ go build
//   $ ./traceroute-caller --help
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"sync"
	"time"

	"github.com/m-lab/traceroute-caller/connection"
	"github.com/m-lab/traceroute-caller/connectionlistener"
	"github.com/m-lab/traceroute-caller/connectionpoller"
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
	// TODO: scamper and its commands (e.g., tracelb) support a
	// relatively large number of flags.  Instead of adding these
	// flags one by one to traceroute-caller flags, going forward
	// it's much better to have traceroute-caller read a configuration
	// file in textproto format that would support all scamper and
	// its command flags.
	scamperBin        = flag.String("scamper.bin", "scamper", "The path to the scamper binary.")
	scattachBin       = flag.String("scamper.sc_attach", "sc_attach", "The path to the sc_attach binary.")
	scwarts2jsonBin   = flag.String("scamper.sc_warts2json", "sc_warts2json", "The path to the sc_warts2json binary.")
	scamperCtrlSocket = flag.String("scamper.unixsocket", "/tmp/scamperctrl", "The name of the UNIX-domain socket that the scamper daemon should listen on.")
	scamperTimeout    = flag.Duration("scamper.timeout", 900*time.Second, "How long to wait to complete a scamper trace.")
	scamperPTR        = flag.Bool("scamper.tracelb-ptr", true, "Look up DNS pointer records for IP addresses.")
	scamperWaitProbe  = flag.Int("scamper.tracelb-W", 25, "How long to wait between probes in 1/100ths of seconds (min 15, max 200).")
	outputPath        = flag.String("outputPath", "/var/spool/scamper", "The path of output.")
	waitTime          = flag.Duration("waitTime", 5*time.Second, "How long to wait between subsequent listings of open connections.")
	poll              = flag.Bool("poll", true, "Whether the polling method should be used to see new connections.")
	tracerType        = flagx.Enum{
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
	if !*poll && *eventsocket.Filename == "" {
		logFatal("either specify poll mode or provide a value for --tcpinfo.eventsocket")
	}
	rtx.Must(os.MkdirAll(*outputPath, 0777), "failed to create data directory")

	defer cancel()
	wg := sync.WaitGroup{}

	promSrv := prometheusx.MustServeMetrics()
	defer func() {
		if err := promSrv.Shutdown(ctx); err != nil {
			log.Printf("failed to shutdown Prometheus (error: %v)\n", err)
		}
	}()

	scamper := &tracer.Scamper{
		Binary:           *scamperBin,
		OutputPath:       *outputPath,
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

	wg.Add(1)
	if *poll {
		go func() {
			connPoller := connectionpoller.New(ipCache)
			for ctx.Err() == nil {
				connPoller.TraceClosedConnections()

				select {
				case <-time.After(*waitTime):
				case <-ctx.Done():
				}
			}
			wg.Done()
		}()
	} else {
		go func() {
			localIPs, err := connection.NewLocalIPs()
			rtx.Must(err, "failed to discover local IPs")
			ipserviceClient := ipservice.NewClient(*ipservice.SocketFilename)
			hopAnnotator := hopannotation.New(ipserviceClient, *outputPath)
			connListener := connectionlistener.New(localIPs, ipCache, hopAnnotator)
			eventsocket.MustRun(ctx, *eventsocket.Filename, connListener)
			wg.Done()
		}()
	}
	wg.Wait()
}
