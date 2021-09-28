package main

import (
	"context"
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"

	"github.com/m-lab/go/prometheusx"
	"github.com/m-lab/go/prometheusx/promtest"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/eventsocket"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func TestMetrics(t *testing.T) {
	promtest.LintMetrics(t)
}

func TestMainWithConnectionListener(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestMainWithConnectionListener")
	rtx.Must(err, "failed to create temp dir")
	defer os.RemoveAll(dir)
	srv := eventsocket.New(dir + "/events.sock")
	rtx.Must(srv.Listen(), "failed to start the empty server")

	*prometheusx.ListenAddress = ":0"
	*eventsocket.Filename = dir + "/events.sock"
	*tracerouteOutput = dir
	*hopAnnotationOutput = dir

	ctx, cancel = context.WithCancel(context.Background())
	go func(t *testing.T) {
		if err := srv.Serve(ctx); err != nil {
			t.Logf("failed to start eventsocket server (error: %v)", err)
		}
	}(t)
	go func() {
		time.Sleep(1 * time.Second)
		cancel()
	}()
	main()
}

func TestMainWithBadArgs(t *testing.T) {
	*eventsocket.Filename = ""
	*tracerouteOutput = "/tmp/"
	*hopAnnotationOutput = "/tmp/"

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
