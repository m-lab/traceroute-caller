package scamper

import (
	"context"
	"log"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/m-lab/go/rtx"
	"github.com/m-lab/traceroute-caller/connection"
	pipe "gopkg.in/m-lab/pipe.v3"
)

// Daemon contains a single instance of a scamper process. Once the Daemon has
// been started, you can call Trace and then all traces will be centrally run
// and managed.
type Daemon struct {
	Binary, AttachBinary, Warts2JSONBinary, ControlSocket, OutputPath string
}

// MustStart starts a scamper binary running and listening to the given context.
// We expect this function to be mostly used as a goroutine:
//    go d.MustStart(ctx)
func (d *Daemon) MustStart(ctx context.Context) {
	derivedCtx, derivedCancel := context.WithCancel(ctx)
	defer derivedCancel()
	if _, err := os.Stat(d.ControlSocket); !os.IsNotExist(err) {
		log.Fatal("The control socket file must not already exist")
	}
	defer os.Remove(d.ControlSocket)
	command := exec.Command(d.Binary, "-U", d.ControlSocket)
	// Start is non-blocking.
	rtx.Must(command.Start(), "Could not start daemon")

	go func() {
		err := command.Wait()
		log.Printf("Scamper exited with error: %v\n", err)
		derivedCancel()
	}()

	<-derivedCtx.Done()
	// This will only kill the scamper daemon when executed by root, because the
	// scamper binary is suid root a user can't kill processes owned by root, even
	// if the user started those processes. This is also why we don't use
	// CommandContext in the exec package - if the process isn't successfully
	// killed by SIGKILL, then the code in that package doesn't work correctly.
	command.Process.Signal(syscall.SIGKILL)
}

// createTimePath returns a string with date in format yyyy/mm/dd/hostname/
func (d *Daemon) createTimePath() string {
	dir := d.OutputPath + "/" + time.Now().Format("2006/01/02") + "/"
	rtx.Must(os.MkdirAll(dir, 0700), "Could not create the output dir")
	return dir
}

// Trace starts a sc_attach connecting to the scamper process for each connection.
func (d *Daemon) Trace(conn connection.Connection) {
	filepath := d.createTimePath()
	uuid, err := conn.UUID()
	rtx.Must(err, "Could not create UUID from connection - this should never happen")
	filename := filepath + "/" + uuid + ".json"
	cmd := pipe.Line(
		pipe.Println("tracelb -P icmp-echo -q 3 -O ptr ", conn.RemoteIP),
		pipe.Exec(d.AttachBinary, "-i-", "-o-", "-U", d.ControlSocket),
		pipe.Exec(d.Warts2JSONBinary),
		pipe.AppendFile(filename, 0666),
	)
	err = pipe.Run(cmd)
	if err != nil {
		log.Printf("Command failed: %v (err: %v)\n", cmd, err)
	}
}
