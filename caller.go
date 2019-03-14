package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/m-lab/traceroute-caller/connectionwatcher"
	"github.com/m-lab/traceroute-caller/scamper"
)

var outputPath = flag.String("outputPath", "/var/spool/scamper", "path of output")

func main() {
	var connWatcher connectionwatcher.ConnectionWatcher
	if len(os.Args) > 1 {
		*outputPath = os.Args[1]
	}
	connWatcher.GetConnections()
	for true {
		closedCollection := connWatcher.GetClosedCollection()
		fmt.Printf("length of closed connections: %d\n", len(closedCollection))
		for _, conn := range closedCollection {
			log.Printf("PT start: %s %d", conn.Remote_ip, conn.Remote_port)
			go scamper.Run(conn, *outputPath)
		}
		time.Sleep(5 * time.Second)
	}
}
