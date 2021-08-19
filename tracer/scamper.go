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
	"strings"
	"syscall"
	"time"

	"github.com/m-lab/go/rtx"
	"github.com/m-lab/go/shx"
	"github.com/m-lab/traceroute-caller/connection"
	"github.com/m-lab/uuid"
)

// Scamper uses scamper in non-daemon mode to perform traceroutes. This is much
// less efficient, but when scamper crashes, it has a much lower "blast radius".
type Scamper struct {
	Binary, OutputPath string
	ScamperTimeout     time.Duration
	TracelbPTR         bool
	TracelbWaitProbe   int
}

// generatesFilename creates the string filename for storing the data.
func generateFilename(path string, cookie string, t time.Time) (string, error) {
	dir, err := createDatePath(path, t)
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
	// TODO Is this still useful?  Does shx.PipeJob we ever panic?
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
func (s *Scamper) trace(conn connection.Connection, t time.Time) ([]byte, error) {
	// Make sure a directory path based on the current date exists,
	// generate a filename to save in that directory, and create
	// a buffer to hold traceroute data.
	filename, err := generateFilename(s.OutputPath, conn.Cookie, t)
	if err != nil {
		return nil, err
	}
	// Create a context and initialize command execution variables.
	ctx, cancel := context.WithTimeout(context.Background(), s.ScamperTimeout)
	defer cancel()
	tracelbCmd := []string{"tracelb", "-P", "icmp-echo", "-q", "3", "-W", strconv.Itoa(s.TracelbWaitProbe)}
	if s.TracelbPTR {
		tracelbCmd = append(tracelbCmd, []string{"-O", "ptr"}...)
	}
	tracelbCmd = append(tracelbCmd, conn.RemoteIP)
	iVal := strings.Join(tracelbCmd, " ")
	cmd := shx.Pipe(
		shx.Exec(s.Binary, "-I", iVal, "-o-", "-O", "json"),
	)

	return traceAndWrite(ctx, "scamper", filename, cmd, conn, t)
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
	cmdFlags := []string{"-U", d.ControlSocket, "-p", "10000"}
	command := exec.Command(d.Binary, cmdFlags...)
	// Start is non-blocking.
	log.Printf("Starting scamper as a daemon: %s %s\n", d.Binary, strings.Join(cmdFlags, " "))
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
func (d *ScamperDaemon) Trace(conn connection.Connection, t time.Time) (out []byte, err error) {
	// TODO Is this still useful?  Does shx.PipeJob we ever panic?
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
		go func(c connection.Connection) {
			_, _ = d.Trace(c, time.Now())
		}(c)
	}
}

func (d *ScamperDaemon) trace(conn connection.Connection, t time.Time) ([]byte, error) {
	// Make sure a directory path based on the current date exists,
	// generate a filename to save in that directory, and create
	// a buffer to hold traceroute data.
	filename, err := generateFilename(d.OutputPath, conn.Cookie, t)
	if err != nil {
		return nil, err
	}

	// Create a context and initialize command execution variables.
	ctx, cancel := context.WithTimeout(context.Background(), d.ScamperTimeout)
	defer cancel()
	tracelbCmd := []string{"tracelb", "-P", "icmp-echo", "-q", "3", "-W", strconv.Itoa(d.TracelbWaitProbe)}
	if d.TracelbPTR {
		tracelbCmd = append(tracelbCmd, []string{"-O", "ptr"}...)
	}
	tracelbCmd = append(tracelbCmd, conn.RemoteIP)
	scAttachCmd := []string{d.AttachBinary, "-i-", "-o-", "-U", d.ControlSocket}
	cmd := shx.Pipe(
		shx.Exec("echo", tracelbCmd...),
		shx.Exec(scAttachCmd[0], scAttachCmd[1:]...),
		shx.Exec(d.Warts2JSONBinary),
	)

	return traceAndWrite(ctx, "scamper-daemon", filename, cmd, conn, t)
}

func traceAndWrite(ctx context.Context, label string, fn string, cmd shx.Job, conn connection.Connection, t time.Time) ([]byte, error) {
	data, err := runTrace(ctx, label, cmd, conn)
	if err != nil {
		return nil, err
	}
	return writeTraceFile(data, fn, conn, t)
}

// runTrace executes a trace command and returns the data.
func runTrace(ctx context.Context, label string, cmd shx.Job, conn connection.Connection) ([]byte, error) {
	var desc shx.Description
	deadline, _ := ctx.Deadline()
	timeout := time.Until(deadline)
	cmd.Describe(&desc)
	log.Printf("Trace started: %s\n", desc.String())

	// Add buffer write at end of cmd.
	buff := bytes.Buffer{}
	fullCmd := shx.Pipe(cmd, shx.Write(&buff))

	start := time.Now()
	err := fullCmd.Run(ctx, shx.New())
	latency := time.Since(start).Seconds()
	log.Printf("Trace returned in %v seconds", latency)
	tracesPerformed.WithLabelValues(label).Inc()
	if err != nil {
		// TODO change to use a label within general trace counter.
		// possibly just use the latency histogram?
		crashedTraces.WithLabelValues(label).Inc()

		traceTimeHistogram.WithLabelValues("error").Observe(latency)
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			log.Printf("Trace timed out after %v\n", timeout)
		} else {
			log.Printf("Trace failed in context %p (error: %v)\n", ctx, err)
		}
		return buff.Bytes(), err
	}

	log.Printf("Trace succeeded in context %p\n", ctx)
	traceTimeHistogram.WithLabelValues("success").Observe(latency)
	return buff.Bytes(), nil
}

// TODO - this should take an io.Writer?
func writeTraceFile(data []byte, fn string, conn connection.Connection, t time.Time) ([]byte, error) {
	buff := bytes.Buffer{}
	// buff.Write err is alway nil, but it may OOM
	_, _ = buff.Write(GetMetaline(conn, false, ""))
	_, _ = buff.Write(data)
	return buff.Bytes(), ioutil.WriteFile(fn, buff.Bytes(), 0666)
}
