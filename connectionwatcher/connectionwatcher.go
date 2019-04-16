// Package connectionwatcher provides a way of discovering what connections are
// currently open, and what connections have recently disappeared.
package connectionwatcher

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/m-lab/traceroute-caller/connection"
	"github.com/m-lab/traceroute-caller/ipcache"
)

var (
	// The new test output filename is joint of hostname, server boot time, and socker TCO cookie.
	// like: myhost.example.com_1548788619_00000000000084FF
	localIPv4 = []string{"127.", "128.112.139.", "::ffff:127.0.0.1"}

	ssBinary = flag.String("ss-binary", "/bin/ss", "The location on disk of the ss binary.")

	// Turned into a variable to enable testing of error cases.
	logFatal = log.Fatal
)

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
	for _, prefix := range localIPv4 {
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
		return nil, errors.New("incomplete line")
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

	output := &connection.Connection{
		RemoteIP:   remoteIP,
		RemotePort: remotePort,
		LocalIP:    localIP,
		LocalPort:  localPort,
		Cookie:     cookie,
	}

	return output, nil
}

type ssFinder struct{}

func (f *ssFinder) GetConnections() map[connection.Connection]struct{} {
	cmd := exec.Command(*ssBinary, "-e")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		logFatal(err)
	}

	lines := strings.Split(out.String(), "\n")
	connectionPool := make(map[connection.Connection]struct{})
	for _, line := range lines {
		conn, err := parseSSLine(line)
		if err == nil {
			connectionPool[*conn] = struct{}{}
		}
	}
	return connectionPool
}

type finder interface {
	GetConnections() map[connection.Connection]struct{}
}

type connectionWatcher struct {
	finder
	recentIPCache  ipcache.RecentIPCache
	connectionPool map[connection.Connection]struct{}
}

// ConnectionWatcher is in interface for an object that returns a list of all
// connections which it previously measured to be open, but it can no longer
// measure to be open.
type ConnectionWatcher interface {
	GetClosedConnections() []connection.Connection
}

// GetClosedConnections returns the list of connections which were previously
// measured to be open but were not measured to be open this time..
func (c *connectionWatcher) GetClosedConnections() []connection.Connection {
	oldConn := c.connectionPool
	fmt.Printf("old connection size %d\n", len(oldConn))
	c.connectionPool = c.GetConnections()
	fmt.Printf("new connection size %d\n", len(c.connectionPool))
	var closed []connection.Connection
	for conn := range oldConn {
		if _, hasConn := c.connectionPool[conn]; !hasConn && !c.recentIPCache.Has(conn.RemoteIP) {
			closed = append(closed, conn)
			log.Printf("Try to add " + conn.RemoteIP)
			c.recentIPCache.Add(conn.RemoteIP)
		}
	}
	return closed
}

// New creates and returns a new ConnectionWatcher.
func New() ConnectionWatcher {
	c := &connectionWatcher{
		finder:         &ssFinder{},
		recentIPCache:  *ipcache.New(context.Background()),
		connectionPool: make(map[connection.Connection]struct{}),
	}
	c.GetConnections()
	return c
}
