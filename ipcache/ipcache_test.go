package ipcache_test

import (
	"context"
	"testing"
	"time"

	"github.com/m-lab/traceroute-caller/ipcache"
)

func TestRecentIPCache(t *testing.T) {
	*ipcache.IPCacheTimeout = 2 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tmp := ipcache.New(ctx)
	tmp.Add("1.2.3.4")
	if !tmp.Has("1.2.3.4") {
		t.Error("cache not working correctly")
	}

	time.Sleep(4 * time.Second)
	if tmp.Has("1.2.3.4") {
		t.Error("cache not expire correctly")
	}
}
