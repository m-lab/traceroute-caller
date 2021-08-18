package parser

import (
	"errors"
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
		file     string
		wantErr  error
		wantHops []string
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
		{"invalid-tracelb-links", nil, nil},
		{"valid-simple", nil, []string{}},
		{"valid-complex", nil, []string{
			"2001:4888:36:1002:3a2:1:0:1",
			"2001:550:1b01:1::1",
			"2001:550:3::1ca",
			"2001:4888:3f:6092:3a2:26:0:1",
			"2600:803::79",
			"2600:803:150f::4a"},
		},
	}
	for i, test := range tests {
		// First extract the tracelb line.
		f := filepath.Join("./testdata", test.file)
		t.Logf("Test %v: file: %v", i, f)
		content, err := ioutil.ReadFile(f)
		if err != nil {
			t.Fatalf(err.Error())
		}
		tracelb, err := ExtractTraceLB([]byte(content))
		failed := false
		if err == nil {
			if test.wantErr != nil {
				failed = true
			}
		} else if !errors.Is(err, test.wantErr) {
			failed = true
		}
		if failed {
			t.Fatalf("ExtraceTraceLB(): %v, want %v", err, test.wantErr)
		}
		if !strings.HasPrefix(test.file, "valid") {
			continue
		}

		// Now extract the hops.
		gotHops := ExtractHops(tracelb)
		if test.wantHops != nil && len(gotHops) != len(test.wantHops) {
			t.Fatalf("got %d hops, want %d", len(gotHops), len(test.wantHops))
		}
		if test.wantHops == nil {
			continue
		}
		if !isEqual(gotHops, test.wantHops) {
			t.Fatalf("got %v, want %v", gotHops, test.wantHops)
		}
	}
}

// isEqual returns true if all of the elements in s1 exist in s2.
func isEqual(s1, s2 []string) bool {
	if len(s1) != len(s2) {
		return false
	}
	diff := make(map[string]int, len(s1))
	for _, s := range s1 {
		diff[s]++
	}
	for _, s := range s2 {
		if _, ok := diff[s]; !ok {
			return false
		}
		diff[s]--
		if diff[s] == 0 {
			delete(diff, s)
		}
	}
	return len(diff) == 0
}
