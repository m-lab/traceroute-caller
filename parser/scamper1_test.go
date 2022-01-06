package parser

import (
	"io/ioutil"
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
		{"invalid-num-lines", errTracerouteFile, nil},
		{"invalid-last-line", errTracerouteFile, nil},
		{"invalid-metadata", errMetadata, nil},
		{"invalid-metadata-uuid", errMetadataUUID, nil},
		{"invalid-cycle-start", errCycleStart, nil},
		{"invalid-cycle-start-type", errCycleStartType, nil},
		{"invalid-tracelb", errTracelbLine, nil},
		{"invalid-tracelb-type", errTraceType, nil},
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
		{"valid-star", nil, []string{
			"2804:a8:2:c4::52",
			"2001:41a8:4020:2::12a",
			"2804:a8::200:246:59:198",
			"2001:41a8:4020::f",
			"2804:14d:1800:a4::2",
			"2804:a8::200:244:41:252"},
		},
	}
	for i, test := range tests {
		// Read in the test traceroute output file.
		f := filepath.Join("./testdata/scamper1", test.file)
		t.Logf("\nTest %v: file: %v", i, f)
		content, err := ioutil.ReadFile(f)
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
