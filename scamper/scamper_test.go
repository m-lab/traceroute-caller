package scamper

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/m-lab/traceroute-caller/connection"

	"github.com/m-lab/go/rtx"
)

func TestCancelStopsDaemon(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "CancelStopsDaemon")
	rtx.Must(err, "Could not create tempdir")
	defer os.RemoveAll(tempdir)
	d := Daemon{
		// Let the shell use the path to discover these.
		Binary:           "scamper",
		AttachBinary:     "sc_attach",
		Warts2JSONBinary: "sc_warts2json",
		ControlSocket:    tempdir + "/ctrl",
		OutputPath:       tempdir,
	}
	ctx, cancel := context.WithCancel(context.Background())
	wg := sync.WaitGroup{}
	wg.Add(1)
	done := false
	go func() {
		time.Sleep(time.Duration(100 * time.Millisecond))
		log.Println("Starting the daemon")
		d.MustStart(ctx)
		done = true
		wg.Done()
	}()
	log.Println("About to sleep")

	time.Sleep(time.Duration(200 * time.Millisecond))
	if done {
		t.Error("The function should not be done yet.")
	}
	log.Println("About to cancel()")
	cancel()
	wg.Wait()
	if !done {
		t.Error("wg.Done() but done is still false")
	}
}

func TestExistingFileStopsDaemonCreation(t *testing.T) {
	defer func() {
		logFatal = log.Fatal
	}()
	logFatal = func(args ...interface{}) {
		panic("An error for testing")
	}

	tempdir, err := ioutil.TempDir("", "TestExistingFileStopsDaemonCreation")
	rtx.Must(err, "Could not create tempdir")
	defer os.RemoveAll(tempdir)
	rtx.Must(ioutil.WriteFile(tempdir+"/ctrl", []byte("test"), 0666), "Could not create file")
	d := Daemon{
		// Let the shell use the path to discover these.
		Binary:           "scamper",
		AttachBinary:     "sc_attach",
		Warts2JSONBinary: "sc_warts2json",
		ControlSocket:    tempdir + "/ctrl",
		OutputPath:       tempdir,
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Error("This was supposed to cause a panic")
		}
	}()

	d.MustStart(context.Background())
}

func TestTraceWritesUUID(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "TestTraceWritesUUID")
	rtx.Must(err, "Could not create tempdir")
	defer os.RemoveAll(tempdir)

	// Temporarily set the hostname to a value for testing.
	defer func(oldHn string) {
		hostname = oldHn
	}(hostname)
	hostname = "testhostname"

	d := Daemon{
		AttachBinary:     "echo",
		Warts2JSONBinary: "cat",
		OutputPath:       tempdir,
	}

	c := connection.Connection{
		Cookie: "1",
	}

	faketime := time.Date(2019, time.April, 1, 3, 45, 51, 0, time.UTC)

	d.Trace(c, faketime)

	// Unmarshal the first line of the output file.
	b, err := ioutil.ReadFile(tempdir + "/2019/04/01/testhostname/20190401T034551Z_1.jsonl")
	rtx.Must(err, "Could not read file")

	type metadata struct {
		UUID string
	}
	m := metadata{}
	lines := strings.Split(string(b), "\n")
	if len(lines) < 2 {
		t.Error("Not enough lines in", lines)
	}
	rtx.Must(json.Unmarshal([]byte(lines[0]), &m), "Could not unmarshal")

	uuidChunks := strings.Split(m.UUID, "_")
	if uuidChunks[len(uuidChunks)-1] != "0000000000000001" {
		t.Error("Bad uuid:", m.UUID)
	}
}

func TestRecovery(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "TestRecovery")
	rtx.Must(err, "Could not create tempdir")
	defer os.RemoveAll(tempdir)

	// Temporarily set the hostname to a value for testing.
	defer func(oldHn string) {
		hostname = oldHn
	}(hostname)
	hostname = "testhostname"

	d := Daemon{
		AttachBinary:     "echo",
		Warts2JSONBinary: "cat",
		OutputPath:       tempdir,
	}

	c := connection.Connection{
		Cookie: "not a number in base 16 at all",
	}

	// Run both trace methods.
	d.TraceAll([]connection.Connection{c})
	d.Trace(c, time.Now())
	// If this doesn't crash, then the recovery process works!
}
