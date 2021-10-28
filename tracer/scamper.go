package tracer

import (
	"bytes"
	"context"
	"errors"
	"io/ioutil"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/m-lab/go/shx"
	"github.com/m-lab/uuid"
)

// Scamper invokes an instance of the scamper tool for each traceroute.
type Scamper struct {
	Binary           string
	OutputPath       string
	ScamperTimeout   time.Duration
	TracelbPTR       bool
	TracelbWaitProbe int
}

// Trace starts a new scamper process running the paris-traceroute algorithm to
// every node. This uses more resources per-traceroute, but segfaults in the
// called binaries have a much smaller "blast radius".
func (s *Scamper) Trace(remoteIP, cookie, uuid string, t time.Time) (out []byte, err error) {
	tracesInProgress.WithLabelValues("scamper").Inc()
	defer tracesInProgress.WithLabelValues("scamper").Dec()
	return s.trace(remoteIP, cookie, uuid, t)
}

// TraceFromCachedTrace creates test from cached trace.
func (s *Scamper) TraceFromCachedTrace(uuid, cookie string, t time.Time, cachedTest []byte) error {
	filename, err := generateFilename(s.OutputPath, cookie, t)
	if err != nil {
		log.Printf("failed to generate filename (error: %v)\n", err)
		tracerCacheErrors.WithLabelValues("scamper", err.Error()).Inc()
		return err
	}

	// Remove the first line of cachedTest.
	split := bytes.Index(cachedTest, []byte{'\n'})
	if split <= 0 || split == len(cachedTest) {
		log.Printf("failed to split cached test (split: %v)\n", split)
		tracerCacheErrors.WithLabelValues("scamper", "badcache").Inc()
		return errors.New("invalid cached test")
	}

	// Create and add the first line to the test results.
	newTest := append(createMetaline(uuid, true, extractUUID(cachedTest[:split])), cachedTest[split+1:]...)
	return ioutil.WriteFile(filename, []byte(newTest), 0666)
}

// DontTrace is called when a previous trace that we were waiting for
// fails. It increments a counter that tracks the number of these failures.
func (*Scamper) DontTrace() {
	tracesNotPerformed.WithLabelValues("scamper").Inc()
}

// trace a single connection using scamper as a standalone binary.
func (s *Scamper) trace(remoteIP, cookie, uuid string, t time.Time) ([]byte, error) {
	// Make sure a directory path based on the current date exists,
	// generate a filename to save in that directory, and create
	// a buffer to hold traceroute data.
	filename, err := generateFilename(s.OutputPath, cookie, t)
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
	tracelbCmd = append(tracelbCmd, remoteIP)
	cmd := shx.Exec(s.Binary, "-I", strings.Join(tracelbCmd, " "), "-o-", "-O", "json")
	return traceAndWrite(ctx, "scamper", filename, cmd, uuid)
}

// traceAndWrite runs a traceroute and write the result.
func traceAndWrite(ctx context.Context, label string, filename string, cmd shx.Job, uuid string) ([]byte, error) {
	data, err := runTrace(ctx, label, cmd)
	if err != nil {
		return nil, err
	}

	buff := bytes.Buffer{}
	// It's OK to ignore the return values because err is always nil. If
	// the buffer becomes too large, Write() will panic with ErrTooLarge.
	_, _ = buff.Write(createMetaline(uuid, false, ""))
	_, _ = buff.Write(data)
	// Make the file readable so it won't be overwritten.
	return buff.Bytes(), ioutil.WriteFile(filename, buff.Bytes(), 0444)
}

// runTrace executes a trace command and returns the data.
func runTrace(ctx context.Context, label string, cmd shx.Job) ([]byte, error) {
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

// generateFilename creates the string filename for storing the data.
func generateFilename(path string, cookie string, t time.Time) (string, error) {
	dir, err := createDatePath(path, t)
	if err != nil {
		// TODO(SaiedKazemi): Add metric here.
		return "", errors.New("could not create output directory")
	}
	c, err := strconv.ParseUint(cookie, 16, 64)
	if err != nil {
		log.Printf("failed to parse cookie %v (error: %v)\n", cookie, err)
		tracerCacheErrors.WithLabelValues("scamper", "badcookie").Inc()
		return "", errors.New("failed to parse cookie")
	}
	return dir + t.Format("20060102T150405Z") + "_" + uuid.FromCookie(c) + ".jsonl", nil
}
