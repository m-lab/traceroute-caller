package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/m-lab/traceroute-caller/connection"
        "github.com/m-lab/traceroute-caller/connectionwatcher"
)

var connWatcher ConnectionWatcher

///////////////////////////////////////////////////

func main() {
	if len(os.Args) > 1 {
		OUTPUT_PATH = os.Args[1]
	}
	connWatcher.GetConnections()
	for true {
		closedCollection := connWatcher.GetClosedCollection()
		fmt.Printf("length of closed connections: %d\n", len(closedCollection))
		for _, conn := range closedCollection {
			log.Printf("PT start: %s %d", conn.remote_ip, conn.remote_port)
			go RunScamper(conn)
		}
		time.Sleep(5 * time.Second)
	}
}
