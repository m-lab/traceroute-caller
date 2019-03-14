package scamper

import (
	"strings"
	"testing"
)

func TestMakeFilename(t *testing.T) {
	fn := makeFilename("1.2.3.4")
	if !strings.Contains(fn, "-1.2.3.4.json") {
		t.Errorf("filename not created correctly %s", fn)
	}
}
