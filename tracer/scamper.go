package tracer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
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
	Timeout          time.Duration
	TraceType        string
	TracelbPTR       bool
	TracelbWaitProbe int
}

// Validate validates scamper configuration, returning nil for valid
// and an error for invalid configurations.
func (s *Scamper) Validate() error {
	fileInfo, err := os.Stat(s.Binary)
	if err != nil {
		return fmt.Errorf("failed to stat scamper binary (error: %v)", err)
	}
	fileMode := fileInfo.Mode()
	if !fileMode.IsRegular() {
		return fmt.Errorf("scamper binary is not a regular file")
	}
	if fileMode&0100 == 0 {
		return fmt.Errorf("scamper binary is not executable by owner")
	}

	// Regular traceroutes will soon be added an another valid type.
	switch s.TraceType {
	case "mda": // uses paris-traceroute algorithm
		if s.TracelbWaitProbe < 15 || s.TracelbWaitProbe > 200 {
			return fmt.Errorf("%d: invalid tracelb wait probe value", s.TracelbWaitProbe)
		}
		return nil
	}
	return fmt.Errorf("%s: invalid traceroute type", s.TraceType)
}

// Trace starts a new scamper process to run a traceroute based on the
// traceroute type (e.g., "mda") and saves it in a file.
func (s *Scamper) Trace(remoteIP, cookie, uuid string, t time.Time) (out []byte, err error) {
	tracesInProgress.WithLabelValues("scamper").Inc()
	defer tracesInProgress.WithLabelValues("scamper").Dec()
	return s.trace(remoteIP, cookie, uuid, t)
}

// CachedTrace creates a traceroute from the traceroute cache and saves it in a file.
func (s *Scamper) CachedTrace(uuid, cookie string, t time.Time, cachedTrace []byte) error {
	filename, err := generateFilename(s.OutputPath, cookie, t)
	if err != nil {
		log.Printf("failed to generate filename (error: %v)\n", err)
		tracerCacheErrors.WithLabelValues("scamper", err.Error()).Inc()
		return err
	}

	// Remove the first line of cachedTrace.
	split := bytes.Index(cachedTrace, []byte{'\n'})
	if split <= 0 || split == len(cachedTrace) {
		log.Printf("failed to split cached traceroute (split: %v)\n", split)
		tracerCacheErrors.WithLabelValues("scamper", "badcache").Inc()
		return errors.New("invalid cached traceroute")
	}

	// Create and add the first line to the test results.
	newTest := append(createMetaline(uuid, true, extractUUID(cachedTrace[:split])), cachedTrace[split+1:]...)
	return ioutil.WriteFile(filename, []byte(newTest), 0666)
}

// DontTrace is called when a previous traceroute that we were waiting for
// fails. It increments a counter that tracks the number of these failures.
func (*Scamper) DontTrace() {
	tracesNotPerformed.WithLabelValues("scamper").Inc()
}

// trace runs a traceroute using scamper as a standalone binary. The
// command line to invoke scamper varies depending on the traceroute type
// and its options.
func (s *Scamper) trace(remoteIP, cookie, uuid string, t time.Time) ([]byte, error) {
	// Make sure a directory path based on the current date exists,
	// generate a filename to save in that directory, and create
	// a buffer to hold traceroute data.
	filename, err := generateFilename(s.OutputPath, cookie, t)
	if err != nil {
		return nil, err
	}

	// Initialize command execution variables.
	var traceCmd string
	switch s.TraceType {
	case "mda":
		var ptr string
		if s.TracelbPTR {
			ptr = "-O ptr"
		} else {
			ptr = ""
		}
		traceCmd = fmt.Sprintf("tracelb -P icmp-echo -q 3 -W %s %s %s", strconv.Itoa(s.TracelbWaitProbe), ptr, remoteIP)
	default:
		return nil, fmt.Errorf("%s: invalid traceroute type", s.TraceType)
	}
	// When testing this package, instead of scamper, a different
	// command like echo, yes, and false is used which does not
	// need the scamper command line arguments and can actually
	// fail because of them.
	cmd := []string{s.Binary, "-o-", "-O", "json", "-I", traceCmd}

	// Create a context, run a traceroute, and write the output to file.
	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()
	return traceAndWrite(ctx, "scamper", filename, cmd, uuid)
}

// traceAndWrite runs a traceroute and writes the result.
func traceAndWrite(ctx context.Context, label string, filename string, cmd []string, uuid string) ([]byte, error) {
	data, err := runCmd(ctx, label, cmd)
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

// runCmd runs the given command and returns its output.
func runCmd(ctx context.Context, label string, cmd []string) ([]byte, error) {
	deadline, _ := ctx.Deadline()
	timeout := time.Until(deadline)
	job := shx.Exec(cmd[0], cmd[1:]...)
	buff := bytes.Buffer{}
	fullCmd := shx.Pipe(job, shx.Write(&buff))

	log.Printf("context %p: command %s started\n", ctx, strings.Join(cmd, " "))
	start := time.Now()
	err := fullCmd.Run(ctx, shx.New())
	latency := time.Since(start).Seconds()
	log.Printf("context %p: command finished in %v seconds", ctx, latency)
	tracesPerformed.WithLabelValues(label).Inc()
	if err != nil {
		// TODO change to use a label within general traceroute counter.
		// possibly just use the latency histogram?
		crashedTraces.WithLabelValues(label).Inc()
		traceTimeHistogram.WithLabelValues("error").Observe(latency)
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			log.Printf("context %p: command timed out after %v\n", ctx, timeout)
		} else {
			log.Printf("context %p: command failed (error: %v)\n", ctx, err)
		}
		return buff.Bytes(), err
	}

	log.Printf("Command succeeded in context %p\n", ctx)
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
