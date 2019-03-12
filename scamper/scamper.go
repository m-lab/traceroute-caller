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

	"github.com/m-lab/traceroute-caller/connection"
)

var SCAMPER_BIN = flag.String("SCAMPER_BIN", "/usr/local/bin/scamper", "path of scamper binary")


// CreateTimePath returns a string with date in format yyyy/mm/dd/hostname/
func CreateTimePath(prefix string) string {
	currentTime := time.Now().Format("2006-01-02")
	date := strings.Split(currentTime, "-")
	if len(date) != 3 {
		return ""
	}
	if _, err := os.Stat(prefix); os.IsNotExist(err) {
		os.Mkdir(prefix, 0700)
	}
	if _, err := os.Stat(prefix + "/" + date[0]); os.IsNotExist(err) {
		os.Mkdir(prefix+date[0], 0700)
	}
	if _, err := os.Stat(prefix + "/" + date[0] + "/" + date[1]); os.IsNotExist(err) {
		os.Mkdir(prefix+date[0]+"/"+date[1], 0700)
	}
	if _, err := os.Stat(prefix + "/" + date[0] + "/" + date[1] + "/" + date[2]); os.IsNotExist(err) {
		os.Mkdir(prefix+date[0]+"/"+date[1]+"/"+date[2], 0700)
	}
	hostnamePrefix := GetHostnamePrefix()
	if _, err := os.Stat(prefix + "/" + date[0] + "/" + date[1] + "/" + date[2] + "/" + hostnamePrefix); os.IsNotExist(err) {
		os.Mkdir(prefix+date[0]+"/"+date[1]+"/"+date[2]+"/"+hostnamePrefix, 0700)
	}
	return prefix + "/" + date[0] + "/" + date[1] + "/" + date[2] + "/" + hostnamePrefix + "/"
}

// MakeFilename as logtime_clientIP.json, such as:
// 2019-02-04T18:01:10Z-76.14.89.46.json
func MakeFilename(ip string) string {
	t := time.Now()
	return fmt.Sprintf("%s-%s.json", t.Format(time.RFC3339), ip)

}

// GetHostname returns the hostname.
func GetHostname() string {
	hostname, _ := exec.Command("hostname").Output()
	out := string(hostname)
	return strings.TrimSuffix(out, "\n")
}

// GetHostnamePrefix returns first two seg, like "mlab1.ath03" from hostname.
func GetHostnamePrefix() string {
	hostname := GetHostname()
	segs := strings.Split(hostname, ".")
	if len(segs) < 2 {
		return hostname
	}
	return segs[0] + "." + segs[1]
}

// Run start a scamper process for each connection.
func Run(conn connection.Connection, outputPath string) {
	command := exec.Command(*SCAMPER_BIN, "-O", "json", "-I", "tracelb -P icmp-echo -q 3 -O ptr "+conn.Remote_ip)
	uuid, err := connection.MakeUUID(conn.Cookie)
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
		log.Printf("call not exit correctly")
		return
	}

	filepath := CreateTimePath(outputPath)
	log.Println(filepath)

	filename := MakeFilename(conn.Remote_ip)

	f, err := os.Create(filepath + filename)
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
