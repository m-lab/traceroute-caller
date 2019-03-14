package connectionwatcher

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/m-lab/traceroute-caller/connection"
	"github.com/m-lab/traceroute-caller/ipcache"
)

// The new test output filename is joint of hostname, server boot time, and socker TCO cookie.
// like: pboothe2.nyc.corp.google.com_1548788619_00000000000084FF
var IGNORE_IPV4_NETS = []string{"127.", "128.112.139.", "::ffff:127.0.0.1"}

// parseIPAndPort returns a valid IP and port from "ss -e" output.
func parseIPAndPort(input string) (string, int, error) {
	seperator := strings.LastIndex(input, ":")
	if seperator == -1 {
		return "", 0, errors.New("cannot parse IP and port correctly")
	}
	IPStr := input[0:seperator]
	if IPStr[0] == '[' {
		IPStr = IPStr[1 : len(IPStr)-1]
	}
	for _, prefix := range IGNORE_IPV4_NETS {
		if strings.HasPrefix(IPStr, prefix) {
			return "", 0, errors.New("ignore this IP address")
		}
	}
	outputIP := net.ParseIP(IPStr)
	if outputIP == nil {
		return "", 0, errors.New("invalid IP address")
	}

	port, err := strconv.Atoi(input[seperator+1:])
	if err != nil {
		return "", 0, errors.New("invalid IP port")
	}
	return IPStr, port, nil
}

// parseCookie returns cookie from "ss -e" output.
func parseCookie(input string) (string, error) {
	if !strings.HasPrefix(input, "sk:") {
		return "", errors.New("no cookie")
	}
	return input[3:], nil
}

// parseSSLine take one line output from "ss -e" and return the parsed connection.
func parseSSLine(line string) (*connection.Connection, error) {
	segments := strings.Fields(line)
	if len(segments) < 6 {
		return nil, errors.New("Incomplete line")
	}
	if segments[0] != "tcp" || segments[1] != "ESTAB" {
		return nil, errors.New("not a TCP connection")
	}
	localIP, localPort, err := parseIPAndPort(segments[4])
	if err != nil {
		return nil, err
	}

	remoteIP, remotePort, err := parseIPAndPort(segments[5])
	if err != nil {
		return nil, err
	}

	cookie, err := parseCookie(segments[8])
	if err != nil {
		return nil, err
	}

	output := &connection.Connection{Remote_ip: remoteIP, Remote_port: remotePort, Local_ip: localIP, Local_port: localPort, Cookie: cookie}
	return output, nil
}

type ConnectionWatcher struct {
	recentIPCache  ipcache.RecentIPCache
	connectionPool map[connection.Connection]bool
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
	c.connectionPool = make(map[connection.Connection]bool)
	for _, line := range lines {
		conn, err := parseSSLine(line)
		if err == nil {
			c.connectionPool[*conn] = true
		}
	}
}

func (c *ConnectionWatcher) GetPoolSize() int {
	return len(c.connectionPool)
}

func (c *ConnectionWatcher) GetCacheSize() int {
	return c.recentIPCache.Len()
}

func (c *ConnectionWatcher) GetClosedCollection() []connection.Connection {
	oldConn := c.connectionPool
	fmt.Printf("old connection size %d\n", len(oldConn))
	c.GetConnections()
	fmt.Printf("new connection size %d\n", len(c.connectionPool))
	var closed []connection.Connection
	for conn, _ := range oldConn {
		if !c.connectionPool[conn] && !c.recentIPCache.Has(conn.Remote_ip) {
			closed = append(closed, conn)
			log.Printf("Try to add " + conn.Remote_ip)
			c.recentIPCache.Add(conn.Remote_ip)
			log.Printf("cache length : %d at %d", c.recentIPCache.Len(), time.Now().Unix())
		}
	}
	return closed
}

func (c *ConnectionWatcher) Init() {
	c.recentIPCache.New()
	c.connectionPool = make(map[connection.Connection]bool)
}
