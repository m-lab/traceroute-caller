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
		file             string
		wantStartTimeErr error
		wantTraceLBErr   error
		wantHops         []string
	}{
		{"invalid-num-lines", errNumLines, errNumLines, nil},
		{"invalid-cycle-start", errCycleStart, errCycleStart, nil},
		{"invalid-cycle-start-type", errCycleStartType, errCycleStartType, nil},
		{"invalid-tracelb", nil, errTracelb, nil},
		{"invalid-tracelb-type", nil, errTracelbType, nil},
		{"invalid-cycle-stop", nil, errCycleStop, nil},
		{"invalid-cycle-stop-type", nil, errCycleStopType, nil},
		// XXX The original code expected no errors from parsing
		//     this file although its comments read:
		//     Last object on the "type":"tracelb" line has "linkc":1 but no "links" set.
		{"invalid-tracelb-links", nil, nil, nil},
		{"valid-simple", nil, nil, []string{}},
		{"valid-complex", nil, nil, []string{
			"2001:4888:36:1002:3a2:1:0:1",
			"2001:550:1b01:1::1",
			"2001:550:3::1ca",
			"2001:4888:3f:6092:3a2:26:0:1",
			"2600:803::79",
			"2600:803:150f::4a"},
		},
	}
	for i, test := range tests {
		// Read in the test traceroute output file.
		f := filepath.Join("./testdata", test.file)
		t.Logf("\nTest %v: file: %v", i, f)
		content, err := ioutil.ReadFile(f)
		if err != nil {
			t.Fatalf(err.Error())
		}

		// Extract the start_time from the cycle-start line.
		_, gotErr := ExtractStartTime([]byte(content))
		if badErr(gotErr, test.wantStartTimeErr) {
			t.Fatalf("ExtractStartTime(): %v, want %v", gotErr, test.wantStartTimeErr)
		}

		// Extract the tracelb line.
		tracelb, gotErr := ExtractTraceLB([]byte(content))
		if badErr(gotErr, test.wantTraceLBErr) {
			t.Fatalf("ExtraceTraceLB(): %v, want %v", gotErr, test.wantTraceLBErr)
		}

		// If the test traceroute output file isn't valid,
		// it won't have any hops to extract.
		if !strings.HasPrefix(test.file, "valid") {
			continue
		}

		// Extract the hops.
		gotHops := ExtractHops(tracelb)
		if !isEqual(gotHops, test.wantHops) {
			t.Fatalf("got %+v, want %+v", gotHops, test.wantHops)
		}
	}
}

func badErr(gotErr, wantErr error) bool {
	bad := false
	if gotErr == nil {
		if wantErr != nil {
			bad = true
		}
	} else if !errors.Is(gotErr, wantErr) {
		bad = true
	}
	return bad
}

// isEqual returns true if all of the elements in s1 exist in s2.
func isEqual(s1, s2 []string) bool {
	if s1 == nil && s2 == nil {
		return true
	}
	if (s1 == nil && s2 != nil) || (s1 != nil && s2 == nil) {
		return false
	}
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
