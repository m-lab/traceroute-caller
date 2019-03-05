package util_test

import (
	"strings"
	"testing"
	"time"

	"github.com/npad/sidestream/util"
)

func TestMakeUUID(t *testing.T) {
	tmp, err := util.MakeUUID("1be3")
	s := strings.Split(tmp, "_")
	if err != nil || len(s) != 3 || s[2] != "0000000000001BE3" {
		t.Error("Test filename incorrect")
	}
}

func TestParseIPAndPort(t *testing.T) {
	ip, port, err := util.ParseIPAndPort("[2620:0:1003:416:a0ad:fd1a:62f:c862]:53890")
	if err != nil || ip != "2620:0:1003:416:a0ad:fd1a:62f:c862" || port != 53890 {
		t.Error("IPv6 and port not parsed correctly")
	}

	ip, port, err = util.ParseIPAndPort("100.101.236.46:56374")
	if err != nil || ip != "100.101.236.46" || port != 56374 {
		t.Error("IPv4 and port not parsed correctly")
	}
}

func TestParseCookie(t *testing.T) {
	cookie, err := util.ParseCookie("sk:1d10")
	if err != nil || cookie != "1d10" {
		t.Error("Cookie not parsed correctly")
	}
}

func xTestRecentIPCache(t *testing.T) {
	var tmp util.RecentIPCache
	tmp.New()
	tmp.Add("1.2.3.4")
	if !tmp.Has("1.2.3.4") {
		t.Error("cache not working correctly")
	}

	time.Sleep(122 * time.Second)
	if tmp.Has("1.2.3.4") {
		t.Error("cache not expire correctly")
	}
}

func TestMakeFilename(t *testing.T) {
	fn := util.MakeFilename("1.2.3.4")
	if !strings.Contains(fn, "-1.2.3.4.json") {
		t.Errorf("filename not created correctly %s", fn)
	}
}
