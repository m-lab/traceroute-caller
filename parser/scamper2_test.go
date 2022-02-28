package parser

import (
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestScamper2Parser(t *testing.T) {
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
		{"invalid-trace", ErrTraceLine, nil},
		{"invalid-trace-type", ErrTraceType, nil},
		{"invalid-cycle-stop", ErrCycleStop, nil},
		{"invalid-cycle-stop-type", ErrCycleStopType, nil},
		{"invalid-trace-links", nil, nil},
		{"valid-simple", nil, []string{}},
		{"valid-complex", nil, []string{
			"192.168.144.1",
			"100.97.99.252",
			"100.96.216.1",
			"100.123.0.49",
			"104.133.8.193",
			"209.85.175.20",
			"108.170.242.254",
			"209.85.243.176",
			"72.14.223.90",
			"4.69.140.198",
			"212.187.137.18",
			"91.189.88.142"}},
		{"valid-star", nil, []string{}}, // all "addr" values are either "*" or ""
	}
	for i, test := range tests {
		// Read in the test traceroute output file.
		f := filepath.Join("./testdata/scamper2", test.file)
		t.Logf("\nTest %v: file: %v", i, f)
		content, err := ioutil.ReadFile(f)
		if err != nil {
			t.Fatalf(err.Error())
		}

		// Extract start_time from the cycle-start line.
		scamperOutput, gotErr := (&scamper2Parser{}).ParseRawData(content)
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
	s2 := Scamper2{
		CycleStart: CyclestartLine{
			StartTime: 1566691268,
		},
	}
	want := time.Unix(1566691268, 0).UTC()
	if got := s2.StartTime(); got != want {
		t.Fatalf("StartTime() = %v, want %v", got, want)
	}
}
