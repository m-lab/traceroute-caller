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
	//"github.com/m-lab/go/uuid"

	"github.com/npad/sidestream/util"
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

// One line of ss output has format like:
// Netid  State      Recv-Q Send-Q                  Local Address:Port                                   Peer Address:Port
func ParseSSLine(line string) (*Connection, error) {
	segments := strings.Fields(line)
	if len(segments) < 6 {
		return nil, errors.New("Incomplete line")
	}
	if segments[0] != "tcp" || segments[1] != "ESTAB" {
		return nil, errors.New("not a TCP connection")
	}
	localIP, localPort, err := util.ParseIPAndPort(segments[4])
	if err != nil {
		return nil, err
	}

	remoteIP, remotePort, err := util.ParseIPAndPort(segments[5])
	if err != nil {
		return nil, err
	}

	cookie, err := util.ParseCookie(segments[8])
	if err != nil {
		return nil, err
	}

	output := &Connection{remote_ip: remoteIP, remote_port: remotePort, local_ip: localIP, local_port: localPort, cookie: cookie}
	//log.Println(output)
	return output, nil
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

type ConnectionWatcher struct {
	recentIPCache  util.RecentIPCache
	connectionPool map[Connection]bool
}

func (c *ConnectionWatcher) GetConnections() {
	cmd := exec.Command("ss", "-e")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}

	lines := strings.Split(out.String(), "\n")
	c.connectionPool = make(map[Connection]bool)
	for _, line := range lines {
		conn, err := ParseSSLine(line)
		if err == nil {
			c.connectionPool[*conn] = true
			//log.Printf("pool add IP: " + conn.remote_ip)
		}
	}
}

func (c *ConnectionWatcher) GetClosedCollection() []Connection {
	oldConn := c.connectionPool
	fmt.Printf("old connection size %d\n", len(oldConn))
	c.GetConnections()
	fmt.Printf("new connection size %d\n", len(c.connectionPool))
	var closed []Connection
	for conn, _ := range oldConn {
		if !c.connectionPool[conn] && !c.recentIPCache.Has(conn.remote_ip) {
			closed = append(closed, conn)
			log.Printf("Try to add " + conn.remote_ip)
			c.recentIPCache.Add(conn.remote_ip)
			log.Printf("cache length : %d at %d", c.recentIPCache.Len(), time.Now().Unix())
		}
	}
	return closed
}

func (c *ConnectionWatcher) Init() {
	c.recentIPCache.New()
	c.connectionPool = make(map[Connection]bool)
}

var connWatcher ConnectionWatcher

///////////////////////////////////////////////////

func main() {
	connWatcher.GetConnections()
	//count := 0
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
