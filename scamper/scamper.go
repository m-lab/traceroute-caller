package scamper

import (
	"context"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/m-lab/go/rtx"
	"github.com/m-lab/traceroute-caller/connection"
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

	// The hostname of the current machine. Only call os.Hostname once, because the
	// result should never change.
	hostname string
)

func init() {
	var err error
	hostname, err = os.Hostname()
	rtx.Must(err, "Could not call os.Hostname")
}

// MustStart starts a scamper binary running and listening to the given context.
// We expect this function to be mostly used as a goroutine:
//    go d.MustStart(ctx)
func (d *Daemon) MustStart(ctx context.Context) {
	derivedCtx, derivedCancel := context.WithCancel(ctx)
	defer derivedCancel()
	if _, err := os.Stat(d.ControlSocket); !os.IsNotExist(err) {
		log.Fatal("The control socket file must not already exist")
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

// createTimePath returns a string with date in format prefix/yyyy/mm/dd/hostname/
func (d *Daemon) createTimePath(t time.Time) string {
	dir := d.OutputPath + "/" + t.Format("2006/01/02") + "/" + hostname + "/"
	rtx.Must(os.MkdirAll(dir, 0777), "Could not create the output dir")
	return dir
}

func (d *Daemon) generateFilename(cookie string, t time.Time) string {
	return t.Format("20060102T150405Z") + "_" + cookie + ".jsonl"
}

// Trace starts a sc_attach connecting to the scamper process for each connection.
func (d *Daemon) Trace(conn *connection.Connection) {
	tracesInProgress.Inc()
	defer tracesInProgress.Dec()

	filename := d.createTimePath(conn.DiscoveryTime) + d.generateFilename(conn.Cookie, conn.DiscoveryTime)
	log.Println("Starting a trace to be put in", filename)

	// Write the UUID as the first line of the file. If we want to add other
	// metadata, this is the place to do it.
	//
	// TODO: decide what other metadata to add to the traceroute output. If we
	// decide to add more, then this quick-and-dirty approach should be converted
	// into proper json.Marshal calls.
	uuid, err := conn.UUID()
	rtx.Must(err, "Could not parse UUID - this should never happen")
	rtx.Must(
		ioutil.WriteFile(filename, []byte("{\"UUID\": \""+uuid+"\"}\n"), 0666),
		"Could not write to file before traceroute")

	cmd := pipe.Line(
		pipe.Println("tracelb -P icmp-echo -q 3 -O ptr ", conn.RemoteIP),
		pipe.Exec(d.AttachBinary, "-i-", "-o-", "-U", d.ControlSocket),
		pipe.Exec(d.Warts2JSONBinary),
		pipe.AppendFile(filename, 0666),
	)
	err = pipe.Run(cmd)
	if err != nil {
		log.Printf("Command failed: %v (err: %v)\n", cmd, err)
	}
}
