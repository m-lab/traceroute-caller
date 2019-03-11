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

	"github.com/m-lab/traceroute-caller/util"
)

var SCAMPER_BIN = "/usr/local/bin/scamper"
var OUTPUT_PATH = "/var/spool/scamper"

type Connection struct {
	remote_ip   string
	remote_port int
	local_ip    string
	local_port  int
	cookie      string
}



func RunScamper(conn Connection) {
	command := exec.Command(SCAMPER_BIN, "-O", "json", "-I", "tracelb -P icmp-echo -q 3 -O ptr "+conn.remote_ip)
	uuid, err := util.MakeUUID(conn.cookie)
	if err != nil {
		return
	}
	log.Println("uuid: " + uuid)

	var outbuf, errbuf bytes.Buffer

	// set the output to our variable
	command.Stdout = &outbuf
	command.Stderr = &errbuf

	err = command.Run()
	if err != nil {
		log.Printf("failed call for: %v", err)
		return
	}

	ws := command.ProcessState.Sys().(syscall.WaitStatus)
	exitCode := ws.ExitStatus()

	if exitCode != 0 {
		log.Printf("call not exit correctly")
		return
	}

	filepath := util.CreateTimePath(OUTPUT_PATH)
	log.Println(filepath)

	filename := util.MakeFilename(conn.remote_ip)

	f, err := os.Create(filepath + filename)
	if err != nil {
		return
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	uuidString := "{\"uuid\":\"" + uuid + "\"}\n"
	n, err := w.WriteString(uuidString + outbuf.String())
	if err != nil {
		return
	}
	fmt.Printf("wrote %d bytes\n", n)
	w.Flush()
}

//////////////////////////////////////////////////////////////


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
