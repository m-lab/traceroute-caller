// The package is not connectionwatcher_test for test unexported funcs
package connectionwatcher

import (
	"log"
	"reflect"
	"testing"

	"github.com/m-lab/traceroute-caller/connection"
)

func TestParseIPAndPort(t *testing.T) {
	ip, port, err := parseIPAndPort("[2620:0:1003:416:a0ad:fd1a:62f:c862]:53890")
	if err != nil || ip != "2620:0:1003:416:a0ad:fd1a:62f:c862" || port != 53890 {
		t.Error("IPv6 and port not parsed correctly")
	}

	ip, port, err = parseIPAndPort("100.101.236.46:56374")
	if err != nil || ip != "100.101.236.46" || port != 56374 {
		t.Error("IPv4 and port not parsed correctly")
	}
}

func TestParseCookie(t *testing.T) {
	cookie, err := parseCookie("sk:1d10")
	if err != nil || cookie != "1d10" {
		t.Error("Cookie not parsed correctly")
	}
}

func TestParseSSLine(t *testing.T) {
	conn, err := parseSSLine("tcp   ESTAB      0      0         [2620:0:1003:416:a0ad:fd1a:62f:c862]:58790                       [2607:f8b0:400d:c0d::81]:5034                  timer:(keepalive,5.980ms,0) ino:6355539 sk:10f3d <->")
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

func TestConnectionWatcher(t *testing.T) {
	connWatcher := New()

	if connWatcher.getPoolSize() != 0 {
		log.Println(connWatcher.getPoolSize())
	}
}
