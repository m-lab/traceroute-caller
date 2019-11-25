package main

import (
	"context"
	"io/ioutil"
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
	// Verify that main doesn't crash, and that it does exit when the context is canceled.
	// TODO: verify more in this test.
	*prometheusx.ListenAddress = ":0"
	*waitTime = time.Nanosecond // Run through the loop a few times.
	ctx, cancel = context.WithCancel(context.Background())
	go func() {
		time.Sleep(1 * time.Second)
		cancel()
	}()
	main()
}

func TestMainWithConnectionListener(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestTracerouteCaller")
	rtx.Must(err, "Could not create temp dir")
	srv := eventsocket.New(dir + "/events.sock")
	rtx.Must(srv.Listen(), "Could not start the empty server")

	*prometheusx.ListenAddress = ":0"
	*eventsocket.Filename = dir + "/events.sock"
	*eventsocketDryRun = true

	ctx, cancel = context.WithCancel(context.Background())
	go srv.Serve(ctx)
	go func() {
		time.Sleep(1 * time.Second)
		cancel()
	}()
	main()
}
