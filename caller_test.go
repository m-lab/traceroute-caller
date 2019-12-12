package main

import (
	"context"
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"

	"github.com/m-lab/tcp-info/eventsocket"

	"github.com/m-lab/go/prometheusx"
	"github.com/m-lab/go/rtx"

	"github.com/m-lab/go/prometheusx/promtest"
)

func TestMetrics(t *testing.T) {
	promtest.LintMetrics(t)
}

func TestMain(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestMain")
	rtx.Must(err, "Could not create temp dir")
	defer os.RemoveAll(dir)

	// Verify that main doesn't crash, and that it does exit when the context is canceled.
	// TODO: verify more in this test.
	*prometheusx.ListenAddress = ":0"
	*scamperCtrlSocket = dir + "/scamper.sock"
	*waitTime = time.Nanosecond // Run through the loop a few times.
	*outputPath = dir
	*poll = true
	tracerType.Value = "scamper"
	ctx, cancel = context.WithCancel(context.Background())
	go func() {
		time.Sleep(1 * time.Second)
		cancel()
	}()
	main()
}

func TestMainWithConnectionListener(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestMainWithConnectionListener")
	rtx.Must(err, "Could not create temp dir")
	defer os.RemoveAll(dir)
	srv := eventsocket.New(dir + "/events.sock")
	rtx.Must(srv.Listen(), "Could not start the empty server")

	*prometheusx.ListenAddress = ":0"
	*scamperCtrlSocket = dir + "/scamper.sock"
	*eventsocket.Filename = dir + "/events.sock"
	*outputPath = dir
	*poll = false
	tracerType.Value = "paris-traceroute"

	ctx, cancel = context.WithCancel(context.Background())
	go srv.Serve(ctx)
	go func() {
		time.Sleep(1 * time.Second)
		cancel()
	}()
	main()
}

func TestMainWithBadArgs(t *testing.T) {
	tracerType.Value = "paris-traceroute"
	*eventsocket.Filename = ""
	*outputPath = "/tmp/"
	*poll = false

	logFatal = func(_ ...interface{}) {
		panic("testpanic")
	}
	defer func() {
		logFatal = log.Fatal
	}()
	defer func() {
		r := recover()
		if r != "testpanic" {
			t.Error("Should have had a panic called testpanic, not", r)
		}
	}()

	main()
}
