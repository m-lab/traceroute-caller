package connection_test

import (
	"strings"
	"testing"

	"github.com/m-lab/traceroute-caller/connection"
)

func TestMakeUUID(t *testing.T) {
	tmp, err := connection.MakeUUID("1be3")
	s := strings.Split(tmp, "_")
	if err != nil || len(s) != 3 || s[2] != "0000000000001BE3" {
		t.Error("Make uuid from cookie incorrect")
	}
}

func TestParseIPAndPort(t *testing.T) {
	ip, port, err := connection.ParseIPAndPort("[2620:0:1003:416:a0ad:fd1a:62f:c862]:53890")
	if err != nil || ip != "2620:0:1003:416:a0ad:fd1a:62f:c862" || port != 53890 {
		t.Error("IPv6 and port not parsed correctly")
	}

	ip, port, err = connection.ParseIPAndPort("100.101.236.46:56374")
	if err != nil || ip != "100.101.236.46" || port != 56374 {
		t.Error("IPv4 and port not parsed correctly")
	}
}

func TestParseCookie(t *testing.T) {
	cookie, err := connection.ParseCookie("sk:1d10")
	if err != nil || cookie != "1d10" {
		t.Error("Cookie not parsed correctly")
	}
}
