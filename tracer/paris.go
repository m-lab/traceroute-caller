package tracer

import (
	"bytes"
	"io/ioutil"
	"log"
	"strconv"
	"time"

	"github.com/m-lab/traceroute-caller/connection"
	"github.com/m-lab/traceroute-caller/ipcache"
	"github.com/m-lab/uuid-annotator/ipservice"
	pipe "gopkg.in/m-lab/pipe.v3"
)

type ParisData struct {
	data []byte
}

func (pd *ParisData) Serialize() string {
	return string(pd.data)
}

func (pd *ParisData) GetData() []byte {
	return pd.data
}

func (pd *ParisData) AnnotateHops(client ipservice.Client) error {
	// TODO: annotate hops using historical Maxmind datasets.
	return nil
}

// Paris implements the ipcache.Tracer interface using paris-traceroute.
type Paris struct {
	Binary, OutputPath string
	Timeout            time.Duration
}

func (p *Paris) filename(uuid string, t time.Time, cached bool) string {
	cacheString := ""
	if cached {
		cacheString = ".cached"
	}
	// Time format designed to be maximally compatible with existing PT parser.
	return t.Format("20060102T15:04:05Z") + "-UUID-" + uuid + cacheString + ".paris"
}

// Trace runs a traceroute to the remote host and port from the loal source port
// using paris-traceroute.
func (p *Paris) Trace(conn connection.Connection, t time.Time) (ipcache.TracerouteData, error) {
	tracesInProgress.WithLabelValues("paris-traceroute").Inc()
	defer tracesInProgress.WithLabelValues("paris-traceroute").Dec()

	uuid, err := conn.UUID()
	if err != nil {
		return nil, err
	}

	buff := bytes.Buffer{}
	cmd := pipe.Line(
		pipe.Exec(
			p.Binary,
			"--dst-port="+strconv.Itoa(conn.RemotePort),
			"--src-port="+strconv.Itoa(conn.LocalPort),
			conn.RemoteIP),
		pipe.Write(&buff),
	)
	err = pipe.RunTimeout(cmd, p.Timeout)
	tracesPerformed.WithLabelValues("paris-traceroute").Inc()
	if err != nil {
		crashedTraces.WithLabelValues("paris-traceroute").Inc()
		return nil, err
	}
	dir, err := createTimePath(p.OutputPath, t)
	if err != nil {
		crashedTraces.WithLabelValues("paris-traceroute").Inc()
		return nil, err
	}
	fn := p.filename(uuid, t, false)
	data := buff.Bytes()
	err = ioutil.WriteFile(dir+fn, data, 0446)
	log.Println("Wrote file", dir+fn)
	return &ParisData{data: data}, err
}

// TraceFromCachedTrace creates a file from a previously-existing traceroute
// result, rather than rerunning the current test.
func (p *Paris) TraceFromCachedTrace(conn connection.Connection, t time.Time, cachedTest ipcache.TracerouteData) error {
	uuid, err := conn.UUID()
	if err != nil {
		tracerCacheErrors.WithLabelValues("paris-traceroute", "uuid").Inc()
		return err
	}
	dir, err := createTimePath(p.OutputPath, t)
	if err != nil {
		tracerCacheErrors.WithLabelValues("paris-traceroute", "mkdir").Inc()
		return err
	}
	fn := p.filename(uuid, t, true)
	return ioutil.WriteFile(dir+fn, cachedTest.(*ParisData).GetData(), 0446)
}

// DontTrace skips tracing entirely. It is used strictly to inform a particular
// tracer about how many traces it is missing out on due to its internal
// problems.
func (p *Paris) DontTrace(conn connection.Connection, err error) {
	tracesNotPerformed.WithLabelValues("paris-traceroute").Inc()
}
