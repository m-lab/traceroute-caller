package ipcache_test

import (
	"context"
	"flag"
	"testing"
	"time"

	"github.com/m-lab/traceroute-caller/ipcache"
)

func TestRecentIPCache(t *testing.T) {
	f := flag.Lookup("IpCacheTimeout")
	f.Value.Set("20")

	tmp := ipcache.New(context.Background())
	tmp.Add("1.2.3.4")
	if !tmp.Has("1.2.3.4") {
		t.Error("cache not working correctly")
	}

	time.Sleep(22 * time.Second)
	if tmp.Has("1.2.3.4") {
		t.Error("cache not expire correctly")
	}
}
