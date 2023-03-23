package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestScamper1Parser(t *testing.T) {
	tests := []struct {
		file     string
		wantErr  error
		wantHops []string
	}{
		{"invalid-num-lines", ErrTracerouteFile, nil},
		{"invalid-last-line", ErrTracerouteFile, nil},
		{"invalid-metadata", ErrMetadata, nil},
		{"invalid-metadata-uuid", ErrMetadataUUID, nil},
		{"invalid-cycle-start", ErrCycleStart, nil},
		{"invalid-cycle-start-type", ErrCycleStartType, nil},
		{"invalid-tracelb", ErrTracelbLine, nil},
		{"invalid-tracelb-type", ErrTraceType, nil},
		{"invalid-cycle-stop", ErrCycleStop, nil},
		{"invalid-cycle-stop-type", ErrCycleStopType, nil},
		{"invalid-tracelb-links", nil, nil},
		{"valid-simple", nil, []string{}},
		{
			"valid-complex", nil, []string{
				"2001:4888:36:1002:3a2:1:0:1",
				"2001:550:1b01:1::1",
				"2001:550:3::1ca",
				"2001:4888:3f:6092:3a2:26:0:1",
				"2600:803::79",
				"2600:803:150f::4a",
			},
		},
		{"valid-star", nil, []string{}}, // all "addr" values are either "*" or ""
	}
	for i, test := range tests {
		// Read in the test traceroute output file.
		f := filepath.Join("./testdata/scamper1", test.file)
		t.Logf("\nTest %v: file: %v", i, f)
		content, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf(err.Error())
		}

		// Extract start_time from the cycle-start line.
		scamperOutput, gotErr := (&scamper1Parser{}).ParseRawData(content)
		if badErr(gotErr, test.wantErr) {
			t.Fatalf("ParseRawData(): %v, want %v", gotErr, test.wantErr)
		}

		// If the test traceroute output file isn't valid,
		// it won't have any hops to extract.
		if !strings.HasPrefix(test.file, "valid") {
			continue
		}

		// Extract the hops.
		gotHops := scamperOutput.ExtractHops()
		if !isEqual(gotHops, test.wantHops) {
			t.Fatalf("got %+v, want %+v", gotHops, test.wantHops)
		}
	}

	// Test StartTime().
	s1 := Scamper1{
		CycleStart: CyclestartLine{
			StartTime: 1566691268,
		},
	}
	want := time.Unix(1566691268, 0).UTC()
	if got := s1.StartTime(); got != want {
		t.Fatalf("StartTime() = %v, want %v", got, want)
	}
}
