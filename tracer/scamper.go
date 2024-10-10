package tracer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrEmptyUUID is returned when a required UUID is empty.
	ErrEmptyUUID = errors.New("uuid is empty")
)

// ScamperConfig contains configuration parameters of scamper.
type ScamperConfig struct {
	Binary         string
	OutputPath     string
	Timeout        time.Duration
	TraceType      string
	TracePTR       bool
	TraceWaitProbe int
	Extension      string
}

// Scamper invokes an instance of the scamper tool for each traceroute.
type Scamper struct {
	binary     string
	outputPath string
	timeout    time.Duration
	cmd        string
	ext        string
}

// NewScamper validates the specified scamper configuration and, if successful,
// returns a new Scamper instance.  Otherwise, it returns nil and an error.
func NewScamper(cfg ScamperConfig) (*Scamper, error) {
	// Validate that the cfg.Binary exists and is an executable file.
	if err := exec.Command("test", "-f", cfg.Binary, "-a", "-x", cfg.Binary).Run(); err != nil {
		return nil, fmt.Errorf("%q: is not an executable file", cfg.Binary)
	}
	// Validate that traceroute files can be saved in cfg.OutputPath.
	if err := os.MkdirAll(cfg.OutputPath, 0777); err != nil {
		return nil, fmt.Errorf("failed to create directory %q (error: %v)", cfg.OutputPath, err)
	}
	dir, err := os.MkdirTemp(cfg.OutputPath, "trc-testdir")
	if err != nil {
		return nil, fmt.Errorf("failed to create a directory inside %q (error: %v)", cfg.OutputPath, err)
	}
	defer os.RemoveAll(dir)
	// Validate that timeout is at least one second and at most an hour.
	if cfg.Timeout < 1*time.Second || cfg.Timeout > 3600*time.Second {
		return nil, fmt.Errorf("%v: invalid timeout value (min: 1s, max 3600s)", cfg.Timeout)
	}
	// See this package's documentation for descriptions of mda
	// and regular traceroutes.
	var traceCmd string
	switch cfg.TraceType {
	case "mda":
		traceCmd = "tracelb -P icmp-echo -q 3"
	case "regular":
		traceCmd = "trace -P icmp-paris -q 3"
	default:
		return nil, fmt.Errorf("%s: invalid traceroute type", cfg.TraceType)
	}
	if cfg.TraceWaitProbe < 15 || cfg.TraceWaitProbe > 200 {
		return nil, fmt.Errorf("%d: invalid tracelb wait probe value", cfg.TraceWaitProbe)
	}
	traceCmd += " -W " + strconv.Itoa(cfg.TraceWaitProbe)
	if cfg.TracePTR {
		traceCmd += " -O ptr"
	}
	ext := cfg.Extension
	if ext == "" {
		ext = "jsonl"
	}
	return &Scamper{
		binary:     cfg.Binary,
		outputPath: cfg.OutputPath,
		timeout:    cfg.Timeout,
		cmd:        traceCmd,
		ext:        ext,
	}, nil
}

// WriteFile writes the given data to a file in the configured Scamper output
// path using the given UUID and time.
func (s *Scamper) WriteFile(uuid string, t time.Time, data []byte) error {
	filename, err := generateFilename(s.outputPath, uuid, s.ext, t)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

// Trace starts a new scamper process to run a traceroute based on the
// traceroute type and saves it in a file.
func (s *Scamper) Trace(remoteIP, uuid string, t time.Time) ([]byte, error) {
	tracesInProgress.WithLabelValues("scamper").Inc()
	defer tracesInProgress.WithLabelValues("scamper").Dec()
	if uuid == "" {
		return nil, ErrEmptyUUID
	}
	return s.trace(remoteIP, uuid, t)
}

// CachedTrace creates an updated traceroute using the given uuid and time based on the traceroute cache.
func (s *Scamper) CachedTrace(uuid string, t time.Time, cachedTrace []byte) ([]byte, error) {
	if uuid == "" {
		return nil, ErrEmptyUUID
	}
	// Remove the first line of the cached traceroute.
	split := bytes.Index(cachedTrace, []byte{'\n'})
	if split <= 0 || split == len(cachedTrace) {
		log.Printf("failed to split cached traceroute (split: %v)\n", split)
		tracerCacheErrors.WithLabelValues("scamper", "badcache").Inc()
		return nil, errors.New("invalid cached traceroute")
	}

	// Create and add the first line to the cached traceroute.
	newTrace := append(createMetaline(uuid, true, extractUUID(cachedTrace[:split])), cachedTrace[split+1:]...)
	return []byte(newTrace), nil
}

// DontTrace is called when a previous traceroute that we were waiting for
// fails. It increments a counter that tracks the number of these failures.
func (*Scamper) DontTrace() {
	tracesNotPerformed.WithLabelValues("scamper").Inc()
}

// trace runs a traceroute using scamper as a standalone binary. The
// command line to invoke scamper varies depending on the traceroute type
// and its options.
func (s *Scamper) trace(remoteIP, uuid string, t time.Time) ([]byte, error) {
	// Create a context, run a traceroute, and return the output.
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	cmd := []string{s.binary, "-o-", "-O", "json", "-I", fmt.Sprintf("%s %s", s.cmd, remoteIP)}
	return traceWithMeta(ctx, "scamper", cmd, uuid)
}

// traceWithMeta runs a traceroute and adds a metadata line to the result.
func traceWithMeta(ctx context.Context, label string, cmd []string, uuid string) ([]byte, error) {
	data, err := runCmd(ctx, label, cmd)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("context %p: failed to obtain a traceroute (command: %v)", ctx, cmd)
	}

	buff := bytes.Buffer{}
	// It's OK to ignore the return values because err is always nil. If
	// the buffer becomes too large, Write() will panic with ErrTooLarge.
	_, _ = buff.Write(createMetaline(uuid, false, ""))
	_, _ = buff.Write(data)
	return buff.Bytes(), nil
}

// runCmd runs the given command and returns its output.
func runCmd(ctx context.Context, label string, cmd []string) ([]byte, error) {
	deadline, _ := ctx.Deadline()
	timeout := time.Until(deadline)

	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	var outb, errb bytes.Buffer
	c.Stdout = &outb
	c.Stderr = &errb
	log.Printf("context %p: command started: %s\n", ctx, strings.Join(cmd, " "))
	start := time.Now()
	err := c.Run()
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
		log.Printf("context %p: standard error: %q\n", ctx, errb.String())
		return outb.Bytes(), err
	}

	log.Printf("context %p: command succeeded\n", ctx)
	traceTimeHistogram.WithLabelValues("success").Observe(latency)
	return outb.Bytes(), nil
}

// generateFilename creates the string filename for storing the data.
func generateFilename(path, uuid, extension string, t time.Time) (string, error) {
	if uuid == "" {
		return "", ErrEmptyUUID
	}
	dir, err := createDatePath(path, t)
	if err != nil {
		// TODO(SaiedKazemi): Add metric here.
		return "", errors.New("failed to create output directory")
	}
	return dir + t.Format("20060102T150405Z") + "_" + uuid + "." + extension, nil
}
