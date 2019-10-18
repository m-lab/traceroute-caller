// Package main provides the traceroute-caller.
package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/rtx"

	"github.com/m-lab/go/prometheusx"
	"github.com/m-lab/traceroute-caller/connectionpoller"
	"github.com/m-lab/traceroute-caller/scamper"
)

var (
	scamperBin        = flag.String("scamper.bin", "scamper", "path of scamper binary")
	scattachBin       = flag.String("scamper.sc_attach", "sc_attach", "path of sc_attach binary")
	scwarts2jsonBin   = flag.String("scamper.sc_warts2json", "sc_warts2json", "path of sc_warts2json binary")
	scamperCtrlSocket = flag.String("scamper.unixsocket", "/tmp/scamperctrl", "The name of the UNIX-domain socket that the scamper daemon should listen on")
	outputPath        = flag.String("outputPath", "/var/spool/scamper", "path of output")
	waitTime          = flag.Duration("waitTime", 5*time.Second, "how long to wait between subsequent listings of open connections")

	ctx, cancel = context.WithCancel(context.Background())
)

// Sample cmd:
// go build
// ./traceroute-caller --outputPath scamper_output
func main() {
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
	go daemon.MustStart(ctx)

	connPoller := connectionpoller.New()
	for ctx.Err() == nil {
		closedConnections := connPoller.GetClosedConnections()
		fmt.Printf("length of closed connections: %d\n", len(closedConnections))
		daemon.TraceAll(closedConnections)

		select {
		case <-time.After(*waitTime):
		case <-ctx.Done():
		}
	}
}
