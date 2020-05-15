// Package tracer takes care of all interaction with traceroute systems.
package tracer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"github.com/m-lab/go/rtx"
	"github.com/m-lab/traceroute-caller/connection"
	"github.com/m-lab/traceroute-caller/ipcache"
	"github.com/m-lab/traceroute-caller/parser"
	"github.com/m-lab/traceroute-caller/schema"
	"github.com/m-lab/uuid"
	"github.com/m-lab/uuid-annotator/annotator"
	"github.com/m-lab/uuid-annotator/ipservice"
	pipe "gopkg.in/m-lab/pipe.v3"
)

// ScamperData implement ipcache.TracerouteData
type ScamperData struct {
	data schema.PTTestRaw
}

func (sd *ScamperData) Serialize() string {
	testStr, err := json.Marshal(sd.data)
	if err == nil {
		return string(testStr)
	}
	return ""
}

func (sd *ScamperData) GetStructureData() schema.PTTestRaw {
	return sd.data
}

func (sd *ScamperData) GetData() []byte {
	testStr, err := json.Marshal(sd.data)
	if err == nil {
		return []byte(testStr)
	}
	return nil
}

func (sd *ScamperData) AnnotateHops(client ipservice.Client) error {
	iplist := parser.ExtractIP(sd.data)
	// Fetch annoatation for the IPs
	ann := make(map[string]*annotator.ClientAnnotations)
	var err error
	if len(iplist) > 0 {
		ann, err = client.Annotate(context.Background(), iplist)
		log.Println(err)
		if err != nil {
			log.Println("Cannot fetch annotation from ip service")
		}
	}

	// add annotation to the final output
	sd.data = parser.InsertAnnotation(ann, sd.data)
	return nil
}

func (sd *ScamperData) CacheTraceroute(newUUID string) ipcache.TracerouteData {
	var newSD ScamperData
	newSD.data = sd.data
	newSD.data.CachedResult = true
	newSD.data.CachedUUID = sd.data.UUID
	newSD.data.UUID = newUUID
	return &newSD
}

// Scamper uses scamper in non-daemon mode to perform traceroutes. This is much
// less efficient, but when scamper crashes, it has a much lower "blast radius".
type Scamper struct {
	Binary, OutputPath string
	ScamperTimeout     time.Duration
}

// generatesFilename creates the string filename for storing the data.
func (*Scamper) generateFilename(cookie string, t time.Time) string {
	c, err := strconv.ParseInt(cookie, 16, 64)
	rtx.PanicOnError(err, "Could not turn cookie into number")
	return t.Format("20060102T150405Z") + "_" + uuid.FromCookie(uint64(c)) + ".json"
}

// New version that create test from cached trace
func (s *Scamper) TraceFromCachedTrace(conn connection.Connection, t time.Time, cachedTest ipcache.TracerouteData) error {
	dir, err := createTimePath(s.OutputPath, t)
	if err != nil {
		log.Println("Could not create directories")
		tracerCacheErrors.WithLabelValues("scamper", "baddir").Inc()
		return err
	}
	filename := dir + s.generateFilename(conn.Cookie, t)
	log.Println("Starting a cached trace to be put in", filename)

	newUUID, _ := conn.UUID()
	newTest := cachedTest.CacheTraceroute(newUUID)

	if err == nil {
		return ioutil.WriteFile(filename, newTest.GetData(), 0666)
	}
	return err
}

// DontTrace does not perform a trace that would have been performed, had the
// previous round not already returned an error. This should increment a counter
// that tracks the number of tests which have been "transitively failed".
func (*Scamper) DontTrace(conn connection.Connection, err error) {
	tracesNotPerformed.WithLabelValues("scamper").Inc()
}

// Trace starts a new scamper process running the paris-traceroute algorithm to
// every node. This uses more resources per-traceroute, but segfaults in the
// called binaries have a much smaller "blast radius".
func (s *Scamper) Trace(conn connection.Connection, t time.Time) (out ipcache.TracerouteData, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered (%v) a crashed trace for %v at %v\n", r, conn, t)
			crashedTraces.WithLabelValues("scamper").Inc()
			err = errors.New(fmt.Sprint(r))
		}
	}()
	tracesInProgress.WithLabelValues("scamper").Inc()
	defer tracesInProgress.WithLabelValues("scamper").Dec()
	return s.trace(conn, t)
}

// trace a single connection using scamper as a standalone binary.
func (s *Scamper) trace(conn connection.Connection, t time.Time) (ipcache.TracerouteData, error) {
	dir, err := createTimePath(s.OutputPath, t)
	rtx.PanicOnError(err, "Could not create directory")
	filename := dir + s.generateFilename(conn.Cookie, t)
	log.Println("Starting a trace to be put in", filename)
	buff := bytes.Buffer{}

	_, err = buff.WriteString(GetMetaline(conn, false, ""))
	rtx.PanicOnError(err, "Could not write to buffer")

	cmd := pipe.Line(
		pipe.Exec(s.Binary, "-I", "tracelb -P icmp-echo -q 3 -O ptr "+conn.RemoteIP, "-o-", "-O", "json"),
		pipe.Write(&buff),
	)
	err = pipe.RunTimeout(cmd, s.ScamperTimeout)
	tracesPerformed.WithLabelValues("scamper").Inc()
	if err != nil && err.Error() == pipe.ErrTimeout.Error() {
		log.Println("TimeOut for Trace: ", cmd)
		return nil, err
	}

	rtx.PanicOnError(err, "Command %v failed", cmd)

	*ipservice.SocketFilename = "/var/local/uuidannotatorsocket/annotator.sock"
	client := ipservice.NewClient(*ipservice.SocketFilename)
	pt, err := parser.ParseRaw(buff.Bytes())
	if err != nil {
		return nil, err
	}

	sd := ScamperData{data: pt}
	err = sd.AnnotateHops(client)
	if err != nil {
		return nil, err
	}
	rtx.PanicOnError(ioutil.WriteFile(filename, sd.GetData(), 0666), "Could not save output to file")
	return &sd, nil
}

// ScamperDaemon contains a single instance of a scamper process. Once the ScamperDaemon has
// been started, you can call Trace and then all traces will be centrally run
// and managed.
//
// This approach has the advantage that all traces are centrally managed, which
// helps prevent problems with overlapping traces. It has the disadvantage that
// all traces are centrally managed, so if the central daemon goes wrong for
// some reason, there is a much larger blast radius.
type ScamperDaemon struct {
	*Scamper
	AttachBinary, Warts2JSONBinary, ControlSocket string
	AnnotationClient                              ipservice.Client
}

// MustStart starts a scamper binary running and listening to the given context.
// There should only be a single instance of scamper being run by
// traceroute-caller, and if it can't start, then traceroutes can not be
// performed.
//
// We expect this function to be mostly used as a goroutine:
//    go d.MustStart(ctx)
func (d *ScamperDaemon) MustStart(ctx context.Context) {
	scamperDaemonRunning.Set(1)
	defer scamperDaemonRunning.Set(0)
	derivedCtx, derivedCancel := context.WithCancel(ctx)
	defer derivedCancel()
	if _, err := os.Stat(d.ControlSocket); !os.IsNotExist(err) {
		logFatal("The control socket file must not already exist: ", err)
	}
	defer os.Remove(d.ControlSocket)
	command := exec.Command(d.Binary, "-U", d.ControlSocket)
	// Start is non-blocking.
	rtx.Must(command.Start(), "Could not start daemon")

	*ipservice.SocketFilename = "/var/local/uuidannotatorsocket/annotator.sock"
	d.AnnotationClient = ipservice.NewClient(*ipservice.SocketFilename)

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

// Trace starts a sc_attach connecting to the scamper process for each
// connection.
//
// All checks inside of this function and its subfunctions should call
// PanicOnError instead of Must because each trace is independent of the others,
// so we should prevent a single failed trace from crashing everything.
func (d *ScamperDaemon) Trace(conn connection.Connection, t time.Time) (out ipcache.TracerouteData, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered (%v) a crashed trace for %v at %v\n", r, conn, t)
			crashedTraces.WithLabelValues("scamper-daemon").Inc()
			err = errors.New(fmt.Sprint(r))
		}
	}()
	tracesInProgress.WithLabelValues("scamper-daemon").Inc()
	defer tracesInProgress.WithLabelValues("scamper-daemon").Dec()
	return d.trace(conn, t)
}

// TraceAll runs N independent traces on N passed-in connections.
func (d *ScamperDaemon) TraceAll(connections []connection.Connection) {
	for _, c := range connections {
		log.Printf("PT start: %s %d", c.RemoteIP, c.RemotePort)
		go d.Trace(c, time.Now())
	}
}

func (d *ScamperDaemon) trace(conn connection.Connection, t time.Time) (ipcache.TracerouteData, error) {
	dir, err := createTimePath(d.OutputPath, t)
	rtx.PanicOnError(err, "Could not create directory")
	filename := dir + d.generateFilename(conn.Cookie, t)
	log.Println("Starting a trace to be put in", filename)
	buff := bytes.Buffer{}

	_, err = buff.WriteString(GetMetaline(conn, false, ""))
	rtx.PanicOnError(err, "Could not write to buffer")

	log.Printf(
		"Running: echo \"tracelb -P icmp-echo -q 3 -O ptr %s\" | %s -i- -o- -U %s | %s > %s\n",
		conn.RemoteIP, d.AttachBinary, d.ControlSocket, d.Warts2JSONBinary, filename)
	cmd := pipe.Line(
		pipe.Println("tracelb -P icmp-echo -q 3 -O ptr ", conn.RemoteIP),
		pipe.Exec(d.AttachBinary, "-i-", "-o-", "-U", d.ControlSocket),
		pipe.Exec(d.Warts2JSONBinary),
		pipe.Write(&buff),
	)
	err = pipe.RunTimeout(cmd, d.ScamperTimeout)
	tracesPerformed.WithLabelValues("scamper-daemon").Inc()
	if err != nil && err.Error() == pipe.ErrTimeout.Error() {
		log.Println("TimeOut for Trace: ", cmd)
		return nil, err
	}

	pt, err := parser.ParseRaw(buff.Bytes())
	if err != nil {
		return nil, err
	}
	sd := ScamperData{data: pt}
	err = sd.AnnotateHops(d.AnnotationClient)

	if err != nil {
		return nil, err
	}
	rtx.PanicOnError(ioutil.WriteFile(filename, sd.GetData(), 0666), "Could not save output to file")
	return &sd, nil
}
