package main

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/m-lab/tcp-info/eventsocket"
)

type strFlag struct {
	flag  string
	value string
}

var (
	testDir  string
	sockPath string
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func TestMain(m *testing.M) {
	var err error
	// testing.M does not have a TempDir() method.
	testDir, err = os.MkdirTemp("", "test-directory")
	if err != nil {
		log.Fatalf("failed to create test directory (error: %v)", err)
	}
	defer os.RemoveAll(testDir)
	sockPath = filepath.Join(testDir, "events.sock")
	os.Exit(m.Run())
}

// TestMainFunc tests that main() succeeds to create a triggertrace
// handler and establish a connection with the eventsocket server.
func TestMainFunc(t *testing.T) {
	saveOSArgs := os.Args
	logFatal = func(args ...interface{}) { panic(args[0]) }
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("main() = %v, want nil", r)
		}
		logFatal = log.Fatal
		os.Args = saveOSArgs
	}()

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
	// Cancel the server's context after one second.
	go func() {
		time.Sleep(1 * time.Second)
		cancel()
	}()

	for _, arg := range []strFlag{
		{"-scamper.bin", "/bin/echo"},
		{"-scamper.trace-type", "mda"},
		{"-scamper.waitprobe", "15"},
		{"-prometheusx.listen-address", ":0"},
		{"-tcpinfo.eventsocket", sockPath},
		{"-traceroute-output", testDir},
		{"-hopannotation-output", testDir},
	} {
		os.Args = append(os.Args, arg.flag, arg.value)
	}
	main()
	select {
	case <-srvDone:
	// Since the server's context was cancelled after one second,
	// two seconds should be long enough for the server to have stopped.
	case <-time.After(2 * time.Second):
		t.Errorf("eventsocket server goroutine still running")
	}
}

// TestMainEventSocket tests that main() fails when a path to tcp-info's
// event socket is not provided.
func TestMainEventSocket(t *testing.T) {
	saveOSArgs := os.Args
	logFatal = func(args ...interface{}) { panic(args[0]) }
	defer func() {
		r := recover()
		checkError(t, r, errEventSocket)
		logFatal = log.Fatal
		os.Args = saveOSArgs
	}()

	ctx, cancel = context.WithCancel(context.Background())
	for _, arg := range []strFlag{
		{"-scamper.bin", "/bin/echo"},
		{"-scamper.trace-type", "mda"},
		{"-scamper.waitprobe", "15"},
		{"-prometheusx.listen-address", ":0"},
		{"-tcpinfo.eventsocket", ""}, // should cause failure
		{"-traceroute-output", testDir},
		{"-hopannotation-output", testDir},
	} {
		os.Args = append(os.Args, arg.flag, arg.value)
	}
	main()
}

// TestMainScamper tests that main() fails when scamper configuration
// isn't valid.
func TestMainScamper(t *testing.T) {
	saveOSArgs := os.Args
	logFatal = func(args ...interface{}) { panic(args[0]) }
	defer func() {
		r := recover()
		checkError(t, r, errScamper)
		logFatal = log.Fatal
		os.Args = saveOSArgs
	}()

	ctx, cancel = context.WithCancel(context.Background())
	for _, arg := range []strFlag{
		{"-scamper.bin", "/bin/echo"},
		{"-scamper.waitprobe", "10"}, // should cause failure (15 <= valid <= 200)
		{"-prometheusx.listen-address", ":0"},
		{"-tcpinfo.eventsocket", sockPath},
		{"-traceroute-output", testDir},
		{"-hopannotation-output", testDir},
	} {
		os.Args = append(os.Args, arg.flag, arg.value)
	}
	main()
}

// TestMainNewHandler tests that main() fails when hop annotation
// configuration for creating a new handler is invalid.
func TestMainNewHandler(t *testing.T) {
	saveOSArgs := os.Args
	logFatal = func(args ...interface{}) { panic(args[0]) }
	defer func() {
		r := recover()
		checkError(t, r, errNewHandler)
		logFatal = log.Fatal
		os.Args = saveOSArgs
	}()

	ctx, cancel = context.WithCancel(context.Background())
	for _, arg := range []strFlag{
		{"-scamper.bin", "/bin/echo"},
		{"-scamper.trace-type", "mda"},
		{"-scamper.waitprobe", "15"},
		{"-prometheusx.listen-address", ":0"},
		{"-tcpinfo.eventsocket", sockPath},
		{"-traceroute-output", testDir},
		{"-hopannotation-output", ""}, // should cause failure
	} {
		os.Args = append(os.Args, arg.flag, arg.value)
	}
	main()
}

func checkError(t *testing.T, r interface{}, want error) {
	t.Helper()
	if r == nil {
		t.Errorf("main() = nil, want %v", want)
	}
	if got := r.(error); !strings.Contains(got.Error(), want.Error()) {
		t.Errorf("main() = %v, want %v", got, want)
	}
}
