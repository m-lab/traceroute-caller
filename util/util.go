package util

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The new test output filename is joint of hostname, server boot time, and socker TCO cookie.
// like: pboothe2.nyc.corp.google.com_1548788619_00000000000084FF
var IGNORE_IPV4_NETS = []string{"127.", "128.112.139.", "::ffff:127.0.0.1"}

// MakeFilename as logtime_clientIP.json, such as:
// 2019-02-04T18:01:10Z-76.14.89.46.json
func MakeFilename(ip string) string {
	t := time.Now()
	return fmt.Sprintf("%s-%s.json", t.Format(time.RFC3339), ip)

}

func GetHostname() string {
	hostname, _ := exec.Command("hostname").Output()
	out := string(hostname)
	return strings.TrimSuffix(out, "\n")
}

func ParseIPAndPort(input string) (string, int, error) {
	seperator := strings.LastIndex(input, ":")
	if seperator == -1 {
		return "", 0, errors.New("cannot parse IP and port correctly")
	}
	IPStr := input[0:seperator]
	if IPStr[0] == '[' {
		IPStr = IPStr[1 : len(IPStr)-1]
	}
	for _, prefix := range IGNORE_IPV4_NETS {
		if strings.HasPrefix(IPStr, prefix) {
			return "", 0, errors.New("ignore this IP address")
		}
	}
	outputIP := net.ParseIP(IPStr)
	if outputIP == nil {
		return "", 0, errors.New("invalid IP address")
	}

	port, err := strconv.Atoi(input[seperator+1:])
	if err != nil {
		return "", 0, errors.New("invalid IP port")
	}
	return IPStr, port, nil
}

func ParseCookie(input string) (string, error) {
	if !strings.HasPrefix(input, "sk:") {
		return "", errors.New("no cookie")
	}
	return input[3:], nil
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

// CreateTimePath return a string with date in format yyyy/mm/dd/
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

// ///////////////////////////////////////////////////////////////////////


