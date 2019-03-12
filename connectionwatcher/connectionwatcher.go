package connectionwatcher

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/m-lab/traceroute-caller/connection"
	"github.com/m-lab/traceroute-caller/ipcache"
)

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
		conn, err := connection.ParseSSLine(line)
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
