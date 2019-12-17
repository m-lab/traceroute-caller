// Package main provides the traceroute-caller.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"sync"
	"time"

	"github.com/m-lab/traceroute-caller/connection"
	"github.com/m-lab/traceroute-caller/tracer"

	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/eventsocket"

	"github.com/m-lab/go/prometheusx"
	"github.com/m-lab/traceroute-caller/connectionlistener"
	"github.com/m-lab/traceroute-caller/connectionpoller"
	"github.com/m-lab/traceroute-caller/ipcache"
)

var (
	scamperBin        = flag.String("scamper.bin", "scamper", "The path to the scamper binary.")
	scattachBin       = flag.String("scamper.sc_attach", "sc_attach", "The path to the sc_attach binary.")
	scwarts2jsonBin   = flag.String("scamper.sc_warts2json", "sc_warts2json", "The path to the sc_warts2json binary.")
	scamperCtrlSocket = flag.String("scamper.unixsocket", "/tmp/scamperctrl", "The name of the UNIX-domain socket that the scamper daemon should listen on")
	scamperTimeout    = flag.Duration("scamper.timeout", 300*time.Second, "how long to wait to complete a scamper trace.")
	parisBin          = flag.String("paris.bin", "paris-traceroute", "The path to the paris-traceroute binary.")
	parisTimeout      = flag.Duration("paris.timeout", 60*time.Second, "how long to wait to complete a paris-traceroute trace.")
	outputPath        = flag.String("outputPath", "/var/spool/scamper", "path of output")
	waitTime          = flag.Duration("waitTime", 5*time.Second, "how long to wait between subsequent listings of open connections")
	poll              = flag.Bool("poll", true, "Whether the polling method should be used to see new connections.")
	tracerType        = flagx.Enum{
		Options: []string{"paris-traceroute", "scamper", "scamper-daemon", "scamper-daemon-with-paris-backup", "scamper-daemon-with-scamper-backup"},
		Value:   "scamper",
	}

	// Variables to aid in testing of main()
	ctx, cancel = context.WithCancel(context.Background())
	logFatal    = log.Fatal
)

func init() {
	flag.Var(&tracerType, "tracetool", "Choose whether paris-traceroute or scamper should be used.")
}

// Sample cmd:
// go build
// ./traceroute-caller --outputPath scamper_output
func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.Parse()
	rtx.Must(flagx.ArgsFromEnv(flag.CommandLine), "Could not get args from environment")
	rtx.Must(os.MkdirAll(*outputPath, 0557), "Could not create data directory")

	defer cancel()
	wg := sync.WaitGroup{}

	promSrv := prometheusx.MustServeMetrics()
	defer promSrv.Shutdown(ctx)

	scamper := &tracer.Scamper{
		Binary:         *scamperBin,
		OutputPath:     *outputPath,
		ScamperTimeout: *scamperTimeout,
	}
	scamperDaemon := &tracer.ScamperDaemon{
		Scamper:          scamper,
		AttachBinary:     *scattachBin,
		Warts2JSONBinary: *scwarts2jsonBin,
		ControlSocket:    *scamperCtrlSocket,
	}
	parisTracer := &tracer.Paris{
		Binary:     *parisBin,
		OutputPath: *outputPath,
		Timeout:    *parisTimeout,
	}

	var cache *ipcache.RecentIPCache

	// Set up the cache three different ways, depending on the trace method requested.
	switch tracerType.Value {
	case "paris-traceroute":
		cache = ipcache.New(ctx, parisTracer, *ipcache.IPCacheTimeout, *ipcache.IPCacheUpdatePeriod)
	case "scamper":
		cache = ipcache.New(ctx, scamper, *ipcache.IPCacheTimeout, *ipcache.IPCacheUpdatePeriod)
	case "scamper-daemon":
		cache = ipcache.New(ctx, scamperDaemon, *ipcache.IPCacheTimeout, *ipcache.IPCacheUpdatePeriod)
		wg.Add(1)
		go func() {
			scamperDaemon.MustStart(ctx)
			// When the scamper daemon dies, cancel main() and exit.
			cancel()
			wg.Done()
		}()
	// These are hacks - the scamper daemon should not fail at all.
	case "scamper-daemon-with-scamper-backup":
		cache = ipcache.New(ctx, scamperDaemon, *ipcache.IPCacheTimeout, *ipcache.IPCacheUpdatePeriod)
		wg.Add(1)
		go func() {
			scamperDaemon.MustStart(ctx)
			// When the scamper daemon dies, switch to scamper
			cache.UpdateTracer(scamper)
			wg.Done()
		}()
	case "scamper-daemon-with-paris-backup":
		cache = ipcache.New(ctx, scamperDaemon, *ipcache.IPCacheTimeout, *ipcache.IPCacheUpdatePeriod)
		wg.Add(1)
		go func() {
			scamperDaemon.MustStart(ctx)
			// When the scamper daemon dies, switch to paris-traceroute.
			cache.UpdateTracer(parisTracer)
			wg.Done()
		}()
	}

	if *poll {
		wg.Add(1)
		go func(c *ipcache.RecentIPCache) {
			connPoller := connectionpoller.New(c)
			for ctx.Err() == nil {
				connPoller.TraceClosedConnections()

				select {
				case <-time.After(*waitTime):
				case <-ctx.Done():
				}
			}
			wg.Done()
		}(cache)
	} else if *eventsocket.Filename != "" {
		wg.Add(1)
		go func() {
			connCreator, err := connection.NewCreator()
			rtx.Must(err, "Could not discover local IPs")
			connListener := connectionlistener.New(connCreator, cache)
			eventsocket.MustRun(ctx, *eventsocket.Filename, connListener)
			wg.Done()
		}()
	} else {
		logFatal("--poll was false but --tcpinfo.eventsocket was set to \"\". This is a nonsensical configuration.")
	}
	wg.Wait()
}
