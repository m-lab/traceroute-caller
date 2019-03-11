package scamper_test

import (
	"strings"
	"testing"

	"github.com/m-lab/traceroute-caller/scamper"
)

func TestMakeFilename(t *testing.T) {
	fn := scamper.MakeFilename("1.2.3.4")
	if !strings.Contains(fn, "-1.2.3.4.json") {
		t.Errorf("filename not created correctly %s", fn)
	}
}
