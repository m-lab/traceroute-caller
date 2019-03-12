package connection_test

import (
	"reflect"
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

func TestParseSSLine(t *testing.T) {
	conn, err := connection.ParseSSLine("tcp   ESTAB      0      0         [2620:0:1003:416:a0ad:fd1a:62f:c862]:58790                       [2607:f8b0:400d:c0d::81]:5034                  timer:(keepalive,5.980ms,0) ino:6355539 sk:10f3d <->")
	if err != nil {
		t.Error("ss output not parsed correctly")
	}
	expected := &connection.Connection{
		Remote_ip:   "2607:f8b0:400d:c0d::81",
		Remote_port: 5034,
		Local_ip:    "2620:0:1003:416:a0ad:fd1a:62f:c862",
		Local_port:  58790,
		Cookie:      "10f3d"}
	if !reflect.DeepEqual(conn, expected) {
		t.Errorf("Expected %v, got %v for parse ss line", expected, conn)
	}

}
