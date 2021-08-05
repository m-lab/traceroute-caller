package parser

import (
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"
	"testing"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func TestParser(t *testing.T) {
	tests := []struct {
		file      string
		errPrefix string
		wantHops  []string
	}{
		{"invalid-num-lines", errNumLines, nil},
		{"invalid-cycle-start", errCycleStart, nil},
		{"invalid-cycle-start-type", errCycleStartType, nil},
		{"invalid-tracelb", errTracelb, nil},
		{"invalid-tracelb-type", errTracelbType, nil},
		{"invalid-cycle-stop", errCycleStop, nil},
		{"invalid-cycle-stop-type", errCycleStopType, nil},
		// XXX The original code expected no errors from parsing
		//     this file although its comments read:
		//     Last object on the "type":"tracelb" line has "linkc":1 but no "links" set.
		{"invalid-tracelb-links", "", nil},
		{"valid-simple", "", []string{}},
		{"valid-complex", "", []string{
			"2001:4888:36:1002:3a2:1:0:1",
			"2001:550:1b01:1::1",
			"2001:550:3::1ca",
			"2001:4888:3f:6092:3a2:26:0:1",
			"2600:803::79",
			"2600:803:150f::4a"},
		},
	}
	for _, test := range tests {
		// First extract the tracelb line.
		content, err := ioutil.ReadFile(filepath.Join("./testdata", test.file))
		if err != nil {
			t.Fatalf(err.Error())
		}
		tracelb, err := ExtractTraceLB([]byte(content))
		failed := false
		if err == nil {
			if test.errPrefix != "" {
				failed = true
			}
		} else if !strings.HasPrefix(err.Error(), test.errPrefix) {
			failed = true
		}
		if failed {
			t.Fatalf("ExtraceTraceLB(): %v, want %v", err, test.errPrefix)
		}
		if !strings.HasPrefix(test.file, "valid") {
			continue
		}

		// Now extract the hops.
		gotHops := ExtractHops(tracelb)
		if test.wantHops != nil && len(gotHops) != len(test.wantHops) {
			t.Fatalf("got %d hops, want %d", len(gotHops), len(test.wantHops))
		}
		if test.wantHops != nil {
			for _, wantHop := range test.wantHops {
				found := false
				for _, gotHop := range gotHops {
					if wantHop == gotHop {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("want hop %v", wantHop)
				}
			}
		}
	}
}
