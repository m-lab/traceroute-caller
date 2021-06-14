// Package tracer takes care of all interaction with traceroute systems.
package tracer

import (
	"bytes"
	"context"
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
	"github.com/m-lab/uuid"
	pipe "gopkg.in/m-lab/pipe.v3"
)

// Scamper uses scamper in non-daemon mode to perform traceroutes. This is much
// less efficient, but when scamper crashes, it has a much lower "blast radius".
type Scamper struct {
	Binary, OutputPath string
	ScamperTimeout     time.Duration
}

// generatesFilename creates the string filename for storing the data.
func generateFilename(path string, cookie string, t time.Time) (string, error) {
	dir, err := createTimePath(path, t)
	if err != nil {
		// TODO add metric here
		return "", errors.New("could not create output directory")
	}
	c, err := strconv.ParseUint(cookie, 16, 64)
	if err != nil {
		// TODO add metric here
		log.Println(err, "converting cookie", cookie)
		return "", errors.New("error converting cookie")
	}
	return dir + t.Format("20060102T150405Z") + "_" + uuid.FromCookie(c) + ".jsonl", nil
}

// TraceFromCachedTrace creates test from cached trace.
func (s *Scamper) TraceFromCachedTrace(conn connection.Connection, t time.Time, cachedTest []byte) error {
	filename, err := generateFilename(s.OutputPath, conn.Cookie, t)
	if err != nil {
		log.Println(err)
		tracerCacheErrors.WithLabelValues("scamper", err.Error()).Inc()
		return err
	}

	// remove the first line of cachedTest
	split := bytes.Index(cachedTest, []byte{'\n'})

	if split <= 0 || split == len(cachedTest) {
		log.Println("Invalid cached test")
		tracerCacheErrors.WithLabelValues("scamper", "badcache").Inc()
		return errors.New("invalid cached test")
	}

	// Get the uuid from the first line of cachedTest
	newTest := append(GetMetaline(conn, true, extractUUID(cachedTest[:split])), cachedTest[split+1:]...)
	return ioutil.WriteFile(filename, []byte(newTest), 0666)
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
func (s *Scamper) Trace(conn connection.Connection, t time.Time) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered (%v) a crashed trace for %v at %v\n", r, conn, t)
			crashedTraces.WithLabelValues("scamper").Inc()
			err = errors.New(fmt.Sprint(r))
		}
	}()
	tracesInProgress.WithLabelValues("scamper").Inc()
	defer tracesInProgress.WithLabelValues("scamper").Dec()
	fn, err := generateFilename(s.OutputPath, conn.Cookie, t)
	if err != nil {
		return nil, err
	}

	cmd := pipe.Line(
		pipe.Exec(s.Binary, "-I", "tracelb -P icmp-echo -q 3 -O ptr "+conn.RemoteIP, "-o-", "-O", "json"),
	)
	out, err = traceAndWrite(fn, cmd, conn, t, s.ScamperTimeout)
	if err != nil {
		// TODO change to use a label within general trace counter.
		// possibly just use the latency histogram?
		crashedTraces.WithLabelValues("scamper").Inc()
		log.Printf("Error running trace for %v:%v\n", conn, err)
	}
	return
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
	if err := command.Process.Signal(syscall.SIGKILL); err != nil {
		log.Printf("failed to send SIGKILL to scamper daemon, error: %v\n", err)
	}
}

// Trace starts a sc_attach connecting to the scamper process for each
// connection.
//
// All checks inside of this function and its subfunctions should call
// PanicOnError instead of Must because each trace is independent of the others,
// so we should prevent a single failed trace from crashing everything.
func (d *ScamperDaemon) Trace(conn connection.Connection, t time.Time) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered (%v) a crashed trace for %v at %v\n", r, conn, t)
			crashedTraces.WithLabelValues("scamper-daemon").Inc()
			err = errors.New(fmt.Sprint(r))
		}
	}()
	tracesInProgress.WithLabelValues("scamper-daemon").Inc()
	defer tracesInProgress.WithLabelValues("scamper-daemon").Dec()
	cmd := pipe.Line(
		pipe.Println("tracelb -P icmp-echo -q 3 -O ptr ", conn.RemoteIP),
		pipe.Exec(d.AttachBinary, "-i-", "-o-", "-U", d.ControlSocket),
		pipe.Exec(d.Warts2JSONBinary),
	)
	fn, err := generateFilename(d.OutputPath, conn.Cookie, t)
	if err != nil {
		return nil, err
	}

	out, err = traceAndWrite(fn, cmd, conn, t, d.ScamperTimeout)
	if err != nil {
		// TODO change to use a label within general trace counter.
		// possibly just use the latency histogram?
		crashedTraces.WithLabelValues("scamper").Inc()
		log.Printf("Error running trace for %v:%v\n", conn, err)
	}
	return
}

// TraceAll runs N independent traces on N passed-in connections.
func (d *ScamperDaemon) TraceAll(connections []connection.Connection) {
	for _, c := range connections {
		log.Printf("PT start: %s %d", c.RemoteIP, c.RemotePort)
		go func(c connection.Connection) {
			_, _ = d.Trace(c, time.Now())
		}(c)
	}
}

func traceAndWrite(fn string, cmd pipe.Pipe, conn connection.Connection, t time.Time, timeout time.Duration) ([]byte, error) {
	data, err := runTrace(cmd, conn, timeout)
	if err != nil {
		return nil, err
	}
	return data, writeTraceFile(data, fn, conn, t)
}

// runTrace executes a trace command and returns the data.
func runTrace(cmd pipe.Pipe, conn connection.Connection, timeout time.Duration) ([]byte, error) {
	// Add buffer write at end of cmd.
	buff := bytes.Buffer{}
	cmd = pipe.Line(cmd, pipe.Write(&buff))

	start := time.Now()
	err := pipe.RunTimeout(cmd, timeout)
	latency := time.Since(start).Seconds()

	if err != nil {
		traceTimeHistogram.WithLabelValues("error").Observe(latency)
		switch err {
		case pipe.ErrTimeout:
			log.Printf("Trace timed out after %v: %v\n", timeout, conn.RemoteIP)
			tracesPerformed.WithLabelValues("timeout").Inc()
			return nil, err
		default:
			tracesPerformed.WithLabelValues("failed").Inc()
			log.Println("trace failed to", conn.RemoteIP)
			return nil, err
		}
	}
	traceTimeHistogram.WithLabelValues("success").Observe(latency)
	tracesPerformed.WithLabelValues("success").Inc()
	return buff.Bytes(), nil
}

// TODO - this should take an io.Writer?
func writeTraceFile(data []byte, fn string, conn connection.Connection, t time.Time) error {
	buff := bytes.Buffer{}
	// buff.Write err is alway nil, but it may OOM
	_, _ = buff.Write(GetMetaline(conn, false, ""))
	_, _ = buff.Write(data)
	return ioutil.WriteFile(fn, buff.Bytes(), 0666)
}
