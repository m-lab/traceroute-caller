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
		{"invalid-num-lines", errTraceroute, nil},
		{"invalid-last-line", errTraceroute, nil},
		{"invalid-metadata", errMetadata, nil},
		{"invalid-metadata-uuid", errMetadataUUID, nil},
		{"invalid-cycle-start", errCycleStart, nil},
		{"invalid-cycle-start-type", errCycleStartType, nil},
		{"invalid-tracelb", errTracelb, nil},
		{"invalid-tracelb-type", errTracelbType, nil},
		{"invalid-cycle-stop", errCycleStop, nil},
		{"invalid-cycle-stop-type", errCycleStopType, nil},
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
		// Read in the test traceroute output file.
		f := filepath.Join("./testdata", test.file)
		t.Logf("\nTest %v: file: %v", i, f)
		content, err := ioutil.ReadFile(f)
		if err != nil {
			t.Fatalf(err.Error())
		}

		// Extract the start_time from the cycle-start line.
		scamperOutput, gotErr := ParseTraceroute(content)
		if badErr(gotErr, test.wantErr) {
			t.Fatalf("ParseTraceroute(): %v, want %v", gotErr, test.wantErr)
		}

		// If the test traceroute output file isn't valid,
		// it won't have any hops to extract.
		if !strings.HasPrefix(test.file, "valid") {
			continue
		}

		// Extract the hops.
		gotHops := ExtractHops(&scamperOutput.Tracelb)
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
