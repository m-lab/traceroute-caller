package connectionwatcher_test

import (
	"log"
	"testing"

	"github.com/m-lab/traceroute-caller/connectionwatcher"
)

func TestConnectionWatcher(t *testing.T) {
	var connWatcher connectionwatcher.ConnectionWatcher
	connWatcher.Init()
	connWatcher.GetConnections()

	if connWatcher.GetPoolSize() != 0 {
		log.Println(connWatcher.GetPoolSize())
	}
}
