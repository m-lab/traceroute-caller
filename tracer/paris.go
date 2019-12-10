package tracer

import (
	"strconv"
	"time"

	"github.com/m-lab/traceroute-caller/connection"
	pipe "gopkg.in/m-lab/pipe.v3"
)

// Paris implements the ipcache.Tracer interface using paris-traceroute.
type Paris struct {
	Binary, OutputPath string
}

func (p *Paris) Trace(conn connection.Connection, t time.Time) (string, error) {
	cmd := pipe.Line(
		pipe.Exec(
			p.Binary,
			"--dst-port="+strconv.Itoa(conn.RemotePort),
			"--src-port="+strconv.Itoa(conn.LocalPort),
			"--icmp",
			conn.RemoteIP),
	)
	pipe.Run(cmd)
	return "", nil
}

func (p *Paris) CreateCacheTest(conn connection.Connection, t time.Time, cachedTest string) {
	return
}

func (p *Paris) DontTrace(conn connection.Connection, err error) {}
