// Package main provides the traceroute-caller.
package main

import (
	"context"
	"flag"
	"log"
	"sync"
	"time"

	"github.com/m-lab/traceroute-caller/connection"

	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/eventsocket"

	"github.com/m-lab/go/prometheusx"
	"github.com/m-lab/traceroute-caller/connectionlistener"
	"github.com/m-lab/traceroute-caller/connectionpoller"
	"github.com/m-lab/traceroute-caller/ipcache"
	"github.com/m-lab/traceroute-caller/scamper"
)

var (
	scamperBin        = flag.String("scamper.bin", "scamper", "path of scamper binary")
	scattachBin       = flag.String("scamper.sc_attach", "sc_attach", "path of sc_attach binary")
	scwarts2jsonBin   = flag.String("scamper.sc_warts2json", "sc_warts2json", "path of sc_warts2json binary")
	scamperCtrlSocket = flag.String("scamper.unixsocket", "/tmp/scamperctrl", "The name of the UNIX-domain socket that the scamper daemon should listen on")
	outputPath        = flag.String("outputPath", "/var/spool/scamper", "path of output")
	waitTime          = flag.Duration("waitTime", 5*time.Second, "how long to wait between subsequent listings of open connections")
	eventsocketDryRun = flag.Bool("tcpinfo.eventsocket.dryrun", false, "Whether the eventsocket machinery should be turned on in print-only mode.")
	poll              = flag.Bool("poll", true, "Whether the polling method should be used to see new connections.")

	ctx, cancel = context.WithCancel(context.Background())
)

// Sample cmd:
// go build
// ./traceroute-caller --outputPath scamper_output
func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.Parse()
	rtx.Must(flagx.ArgsFromEnv(flag.CommandLine), "Could not get args from environment")

	defer cancel()

	promSrv := prometheusx.MustServeMetrics()
	defer promSrv.Shutdown(ctx)

	daemon := scamper.Daemon{
		Binary:           *scamperBin,
		AttachBinary:     *scattachBin,
		Warts2JSONBinary: *scwarts2jsonBin,
		OutputPath:       *outputPath,
		ControlSocket:    *scamperCtrlSocket,
	}
	go func() {
		daemon.MustStart(ctx)
		cancel()
	}()

	wg := sync.WaitGroup{}
	cache := ipcache.New(ctx, &daemon, *ipcache.IPCacheTimeout, *ipcache.IPCacheUpdatePeriod)
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
	}
	if *eventsocket.Filename != "" {
		wg.Add(1)
		go func() {
			connCreator, err := connection.NewCreator()
			rtx.Must(err, "Could not discover local IPs")
			esdaemon := daemon
			esdaemon.DryRun = *eventsocketDryRun
			if *eventsocketDryRun {
				cache = ipcache.New(ctx, &esdaemon, *ipcache.IPCacheTimeout, *ipcache.IPCacheUpdatePeriod)
			}
			connListener := connectionlistener.New(connCreator, cache)
			eventsocket.MustRun(ctx, *eventsocket.Filename, connListener)
			wg.Done()
		}()
	}
	wg.Wait()
}
