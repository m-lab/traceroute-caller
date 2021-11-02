package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/m-lab/tcp-info/eventsocket"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

// TestMainFunc tests that main() succeeds to create a triggertrace
// handler and establish a connection with the eventsocket server.
func TestMainFunc(t *testing.T) {
	saveOSArgs := os.Args
	logFatalf = func(s string, args ...interface{}) { panic(s) }
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("main() = %v, want nil", r)
		}
		logFatalf = log.Fatalf
		os.Args = saveOSArgs
	}()

	dir, err := ioutil.TempDir("", "TestMainFunc")
	if err != nil {
		t.Fatalf("failed to create temporary directory (error: %v)", err)
	}
	defer os.RemoveAll(dir)

	sockPath := filepath.Join(dir, "events.sock")
	srv := eventsocket.New(sockPath)
	if err := srv.Listen(); err != nil {
		t.Fatalf("failed to start the empty server (error: %v)", err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	srvDone := make(chan struct{})
	go func(t *testing.T) {
		if err := srv.Serve(ctx); err != nil && ctx.Err() != context.Canceled {
			t.Logf("failed to start eventsocket server (error: %v, ctx.Err(): %v)", err, ctx.Err())
		}
		close(srvDone)
	}(t)
	go func() {
		time.Sleep(1 * time.Second)
		cancel()
	}()

	for _, arg := range []struct {
		flag  string
		value string
	}{
		{"-prometheusx.listen-address", ":0"},
		{"-tcpinfo.eventsocket", sockPath},
		{"-traceroute-output", dir},
		{"-hopannotation-output", dir},
	} {
		os.Args = append(os.Args, arg.flag, arg.value)
	}
	main()
	select {
	case <-srvDone:
	case <-time.After(1 * time.Second):
		t.Errorf("eventsocket server goroutine still running")
	}
}

// TestMainFuncEventSocket tests that main() fails when a path to
// tcp-info's event socket is not provided.
func TestMainFuncEventSocket(t *testing.T) {
	logFatalf = func(s string, a ...interface{}) { panic(fmt.Sprintf(s, a...)) }
	defer func() {
		if r := recover(); r == nil || !strings.HasPrefix(r.(string), errEventSocket) {
			t.Errorf("main() = %v, want %v", r, errEventSocket)
		}
		logFatalf = log.Fatalf
	}()

	ctx, cancel = context.WithCancel(context.Background())
	for _, arg := range []struct {
		flag  string
		value string
	}{
		{"-tcpinfo.eventsocket", ""}, // empty string is invalid
		{"-traceroute-output", "/dontcare"},
		{"-hopannotation-output", "/dontcare"},
	} {
		os.Args = append(os.Args, arg.flag, arg.value)
	}
	main()
}

// TestMainNewHandler tests that main() fails when hop annotation
// configuration for creating a new handler is invalid.
func TestMainNewHandler(t *testing.T) {
	logFatalf = func(s string, a ...interface{}) { panic(fmt.Sprintf(s, a...)) }
	defer func() {
		if r := recover(); r == nil || !strings.HasPrefix(r.(string), errNewHandler) {
			t.Errorf("main() = %v, want %v", r, errNewHandler)
		}
		logFatalf = log.Fatalf
	}()

	ctx, cancel = context.WithCancel(context.Background())
	for _, arg := range []struct {
		flag  string
		value string
	}{
		{"-tcpinfo.eventsocket", "/dontcare"},
		{"-traceroute-output", "/dontcare"},
		{"-hopannotation-output", ""}, // empty string is invalid
	} {
		os.Args = append(os.Args, arg.flag, arg.value)
	}
	main()
}
