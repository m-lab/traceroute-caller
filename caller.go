package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/m-lab/traceroute-caller/connectionwatcher"
	"github.com/m-lab/traceroute-caller/scamper"
)

// Sample cmd:
// go build
// ./traceroute-caller --outputPath scamper_output
func main() {
	var outputPath string
	flag.StringVar(&outputPath, "outputPath", "/var/spool/scamper", "path of output")
	flag.Parse()

	var connWatcher connectionwatcher.ConnectionWatcher
	connWatcher.Init()
	connWatcher.GetConnections()
	for {
		closedCollection := connWatcher.GetClosedCollection()
		fmt.Printf("length of closed connections: %d\n", len(closedCollection))
		for _, conn := range closedCollection {
			log.Printf("PT start: %s %d", conn.Remote_ip, conn.Remote_port)
			go scamper.Run(conn, outputPath)
		}
		time.Sleep(5 * time.Second)
	}
}
