package ipcache_test

import (
	"context"
	"testing"
	"time"

	"github.com/m-lab/traceroute-caller/ipcache"
)

func TestRecentIPCache(t *testing.T) {
	*ipcache.IPCacheTimeout = 100 * time.Millisecond
	*ipcache.IPCacheUpdatePeriod = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tmp := ipcache.New(ctx)
	tmp.Add("1.2.3.4")
	if !tmp.Has("1.2.3.4") {
		t.Error("cache not working correctly")
	}

	time.Sleep(300 * time.Millisecond)
	if tmp.Has("1.2.3.4") {
		t.Error("cache not expire correctly")
	}
	cancel()
	time.Sleep(200 * time.Millisecond)
}
