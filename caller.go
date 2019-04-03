package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/m-lab/go/prometheusx"
	"github.com/m-lab/traceroute-caller/connectionwatcher"
	"github.com/m-lab/traceroute-caller/scamper"
)

var (
	ctx, cancel = context.WithCancel(context.Background())
)

// Sample cmd:
// go build
// ./traceroute-caller --outputPath scamper_output
func main() {
	var outputPath, prometheusAddr string
	flag.StringVar(&outputPath, "outputPath", "/var/spool/scamper", "path of output")
	flag.StringVar(&prometheusAddr, "promaddr", ":9090", "Address of prometheus server")
	flag.Parse()

	promSrv := prometheusx.MustStartPrometheus(prometheusAddr)
	connWatcher := connectionwatcher.New()
	for ctx.Err() == nil {
		closedCollection := connWatcher.GetClosedCollection()
		fmt.Printf("length of closed connections: %d\n", len(closedCollection))
		for _, conn := range closedCollection {
			log.Printf("PT start: %s %d", conn.Remote_ip, conn.Remote_port)
			go scamper.Run(conn, outputPath)
		}
		time.Sleep(5 * time.Second)
	}
	promSrv.Shutdown(ctx)
}
