// Package scamper takes care of all interaction with the scamper binary.
package scamper

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/m-lab/go/prometheusx"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/traceroute-caller/connection"
	"github.com/m-lab/uuid"
	pipe "gopkg.in/m-lab/pipe.v3"
)

// Daemon contains a single instance of a scamper process. Once the Daemon has
// been started, you can call Trace and then all traces will be centrally run
// and managed.
type Daemon struct {
	Binary, AttachBinary, Warts2JSONBinary, ControlSocket, OutputPath string
}

var (
	tracesInProgress = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "traces_in_progress",
			Help: "The number of traces currently being run",
		})
	crashedTraces = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "traces_crashed_total",
			Help: "The number of traces that have crashed",
		})

	// hostname of the current machine. Only call os.Hostname once, because the
	// result should never change.
	hostname string

	// log.Fatal turned into a variable to aid in testing of error conditions.
	logFatal = log.Fatal
)

func init() {
	var err error
	hostname, err = os.Hostname()
	rtx.Must(err, "Could not call os.Hostname")
}

// MustStart starts a scamper binary running and listening to the given context.
// There should only be a single instance of scamper being run by
// traceroute-caller, and if it can't start, then traceroutes can not be
// performed.
//
// We expect this function to be mostly used as a goroutine:
//    go d.MustStart(ctx)
func (d *Daemon) MustStart(ctx context.Context) {
	derivedCtx, derivedCancel := context.WithCancel(ctx)
	defer derivedCancel()
	if _, err := os.Stat(d.ControlSocket); !os.IsNotExist(err) {
		logFatal("The control socket file must not already exist")
	}
	defer os.Remove(d.ControlSocket)
	command := exec.Command(d.Binary, "-U", d.ControlSocket)
	// Start is non-blocking.
	rtx.Must(command.Start(), "Could not start daemon")

	// Liveness guarantee: either the process will die and then the derived context
	// will be canceled, or the context will be canceled and then the process will
	// be sent SIGKILL. Either way, this function ends with a canceled sub-context
	// and a process that is either dead or processing SIGKILL.
	go func() {
		err := command.Wait()
		log.Printf("Scamper exited with error: %v\n", err)
		derivedCancel()
	}()
	<-derivedCtx.Done()

	// This will only kill the scamper daemon when executed by root, because the
	// scamper binary is suid root a user can't kill processes owned by root, even
	// if the user started those processes. This is also why we don't use
	// CommandContext in the exec package - if the process isn't successfully
	// killed by SIGKILL, then the code in that package doesn't work correctly.
	command.Process.Signal(syscall.SIGKILL)
}

// createTimePath returns a string with date in format
// prefix/yyyy/mm/dd/hostname/ after creating a directory of the same name.
func (d *Daemon) createTimePath(t time.Time) string {
	dir := d.OutputPath + "/" + t.Format("2006/01/02") + "/"
	rtx.PanicOnError(os.MkdirAll(dir, 0777), "Could not create the output dir")
	return dir
}

func (d *Daemon) generateFilename(cookie string, t time.Time) string {
	c, err := strconv.ParseInt(cookie, 16, 64)
	rtx.PanicOnError(err, "Could not turn cookie into number")
	return t.Format("20060102T150405Z") + "_" + uuid.FromCookie(uint64(c)) + ".jsonl"
}

// Trace starts a sc_attach connecting to the scamper process for each
// connection.
//
// All checks inside of this function and its subfunctions should call
// PanicOnError instead of Must because each trace is independent of the others,
// so we should prevent a single failed trace from crashing everything.
func (d *Daemon) Trace(conn connection.Connection, t time.Time) string {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered (%v) a crashed trace for %v at %v\n", r, conn, t)
			crashedTraces.Inc()
		}
	}()
	tracesInProgress.Inc()
	defer tracesInProgress.Dec()
	return d.trace(conn, t)
}

// TraceAll runs N independent traces on N passed-in connections.
func (d *Daemon) TraceAll(connections []connection.Connection) {
	for _, c := range connections {
		log.Printf("PT start: %s %d", c.RemoteIP, c.RemotePort)
		go d.Trace(c, time.Now())
	}
}

// TODO: move this struct to ETL parser.
type Metadata struct {
	UUID                    string
	TracerouteCallerVersion string
	CachedResult            bool
	CachedUUID              string
}

// isCache indicates whether this meta line is for an orignial trace test or a cached test.
// uuis is the original test if isCache is 1.
func GetMetaline(conn connection.Connection, isCache int, cachedUUID string) string {
	// Write the UUID as the first line of the file. If we want to add other
	// metadata, this is the place to do it.
	//
	// TODO: decide what other metadata to add to the traceroute output. If we
	// decide to add more, then this quick-and-dirty approach should be converted
	// into proper json.Marshal calls.
	uuid, err := conn.UUID()
	rtx.PanicOnError(err, "Could not parse UUID - this should never happen")

	meta := Metadata{
		UUID:                    uuid,
		TracerouteCallerVersion: prometheusx.GitShortCommit,
		CachedResult:            bool(isCache == 1),
		CachedUUID:              cachedUUID,
	}

	metaJSON, _ := json.Marshal(meta)

	return string(metaJSON) + "\n"
}

func ExtractUUID(metaline string) string {
	var metaResult Metadata
	err := json.Unmarshal([]byte(metaline), &metaResult)
	if err != nil {
		log.Println("Could not parse cached results:", metaline)
		return ""
	}
	return metaResult.UUID
}

func (d *Daemon) CreateCacheTest(conn connection.Connection, t time.Time, cachedTest string) {
	filename := d.createTimePath(t) + d.generateFilename(conn.Cookie, t)
	log.Println("Starting a cached trace to be put in", filename)

	// remove the first line of cachedTest
	split := strings.Index(cachedTest, "\n")

	if split <= 0 || split == len(cachedTest) {
		log.Println("Invalid cached test")
		return
	}

	// Get the uuid from the first line of cachedTest
	newTest := GetMetaline(conn, 1, ExtractUUID(cachedTest[:split])) + cachedTest[split+1:]
	rtx.PanicOnError(ioutil.WriteFile(filename, []byte(newTest), 0666), "Could not save output to file")
}

func (d *Daemon) trace(conn connection.Connection, t time.Time) string {
	filename := d.createTimePath(t) + d.generateFilename(conn.Cookie, t)
	log.Println("Starting a trace to be put in", filename)
	buff := bytes.Buffer{}

	_, err := buff.WriteString(GetMetaline(conn, 0, ""))
	rtx.PanicOnError(err, "Could not write to buffer")

	cmd := pipe.Line(
		pipe.Println("tracelb -P icmp-echo -q 3 -O ptr ", conn.RemoteIP),
		pipe.Exec(d.AttachBinary, "-i-", "-o-", "-U", d.ControlSocket),
		pipe.Exec(d.Warts2JSONBinary),
		pipe.Write(&buff),
	)
	rtx.PanicOnError(pipe.Run(cmd), "Command %v failed", cmd)
	rtx.PanicOnError(ioutil.WriteFile(filename, buff.Bytes(), 0666), "Could not save output to file")
	return string(buff.Bytes())
}

type Tracer interface {
	Trace(conn connection.Connection, t time.Time) string
	CreateCacheTest(conn connection.Connection, t time.Time, cachedTest string)
}
