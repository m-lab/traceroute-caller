package scamper

import (
	"context"
	"io/ioutil"
	"log"
	"os"
	"sync"
	"testing"
	"time"

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
