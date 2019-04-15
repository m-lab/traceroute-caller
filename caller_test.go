package main

import (
	"context"
	"testing"
	"time"

	"github.com/m-lab/go/prometheusx"

	"github.com/m-lab/go/prometheusx/promtest"
)

func TestMetrics(t *testing.T) {
	promtest.LintMetrics(t)
}

func TestMain(t *testing.T) {
	// Verify that main doesn't crash, and that it does exit when the context is canceled.
	// TODO: verify more in this test.
	*prometheusx.ListenAddress = ":0"
	ctx, cancel = context.WithCancel(context.Background())
	go func() {
		time.Sleep(1 * time.Second)
		cancel()
	}()
	main()
}
