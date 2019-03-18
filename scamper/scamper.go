package scamper

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/m-lab/go/rtx"
	"github.com/m-lab/traceroute-caller/connection"
)

var scamperBin = flag.String("scamperBin", "/usr/local/bin/scamper", "path of scamper binary")

// createTimePath returns a string with date in format yyyy/mm/dd/hostname/
func createTimePath(prefix string) string {
	dir := prefix + "/" + time.Now().Format("2006/01/02") + "/" + getHostnamePrefix()
	rtx.Must(os.MkdirAll(dir, 0700), "Could not create the output dir")
	return dir
}

// makeFilename returns filesname in format logtime_clientIP.json, such as:
// 2019-02-04T18:01:10Z-76.14.89.46.json
func makeFilename(ip string) string {
	t := time.Now()
	return fmt.Sprintf("%s-%s.json", t.Format(time.RFC3339), ip)

}

// getHostnamePrefix returns first two seg, like "mlab1.ath03" from hostname.
func getHostnamePrefix() string {
	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}
	segs := strings.Split(hostname, ".")
	if len(segs) < 2 {
		return hostname
	}
	return segs[0] + "." + segs[1]
}

// Run starts a scamper process for each connection.
// TODO: convert to use sc_attach
func Run(conn connection.Connection, outputPath string) {
	// scamper -I options take a list of scamper commands provided on the command line.
	command := exec.Command(*scamperBin, "-O", "json", "-I", "tracelb -P icmp-echo -q 3 -O ptr "+conn.Remote_ip)
	uuid, err := conn.UUID()
	if err != nil {
		return
	}
	log.Println("uuid: " + uuid)

	var outbuf, errbuf bytes.Buffer

	// set the output to our variable
	command.Stdout = &outbuf
	command.Stderr = &errbuf

	err = command.Run()
	if err != nil {
		log.Printf("failed call for: %v", err)
		return
	}

	ws := command.ProcessState.Sys().(syscall.WaitStatus)
	exitCode := ws.ExitStatus()

	if exitCode != 0 {
		log.Println(command.Path, command.Args, "exited unsuccessfully with code", exitCode)
		return
	}

	filepath := createTimePath(outputPath)
	log.Println(filepath)

	filename := makeFilename(conn.Remote_ip)

	f, err := os.Create(filepath + "/" + filename)
	if err != nil {
		return
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	uuidString := "{\"uuid\":\"" + uuid + "\"}\n"
	n, err := w.WriteString(uuidString + outbuf.String())
	if err != nil {
		return
	}
	fmt.Printf("wrote %d bytes\n", n)
	w.Flush()
}
