package connection

import (
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/m-lab/go/uuid"
)

// The new test output filename is joint of hostname, server boot time, and socker TCO cookie.
// like: pboothe2.nyc.corp.google.com_1548788619_00000000000084FF
var IGNORE_IPV4_NETS = []string{"127.", "128.112.139.", "::ffff:127.0.0.1"}

type Connection struct {
	Remote_ip   string
	Remote_port int
	Local_ip    string
	Local_port  int
	Cookie      string
}

// MakeUUID returns uuid from cookie parsed from "ss -e" output.
func MakeUUID(cookie string) (string, error) {
	// cookie is a hexdecimal string
	result, _ := strconv.ParseUint(cookie, 16, 64)
	return uuid.FromCookie(result)
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

// ParseSSLine take one line output from "ss -e" and return the parsed connection.
func ParseSSLine(line string) (*Connection, error) {
	segments := strings.Fields(line)
	if len(segments) < 6 {
		return nil, errors.New("Incomplete line")
	}
	if segments[0] != "tcp" || segments[1] != "ESTAB" {
		return nil, errors.New("not a TCP connection")
	}
	localIP, localPort, err := ParseIPAndPort(segments[4])
	if err != nil {
		return nil, err
	}

	remoteIP, remotePort, err := ParseIPAndPort(segments[5])
	if err != nil {
		return nil, err
	}

	cookie, err := ParseCookie(segments[8])
	if err != nil {
		return nil, err
	}

	output := &Connection{Remote_ip: remoteIP, Remote_port: remotePort, Local_ip: localIP, Local_port: localPort, Cookie: cookie}
	return output, nil
}
