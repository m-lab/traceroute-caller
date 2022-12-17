package parser

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/m-lab/go/anonymize"
	"github.com/m-lab/go/testingx"
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
	for _, test := range tests {
		t.Run(test.file, func(t *testing.T) {
			// Read in the test traceroute output file.
			f := filepath.Join("./testdata/scamper2", test.file)
			content, err := os.ReadFile(f)
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
				return
			}

			// Extract the hops.
			gotHops := scamperOutput.ExtractHops()
			if !isEqual(gotHops, test.wantHops) {
				t.Fatalf("got %+v, want %+v", gotHops, test.wantHops)
			}
		})
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

func TestScamper2_AnonymizeHops(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		anon    anonymize.IPAnonymizer
		client  net.IP
		wantErr bool
	}{
		{
			name: "success-simple",
			file: "valid-simple",
			anon: anonymize.New(anonymize.None),
		},
		{
			name: "success-complex",
			file: "valid-complex",
			anon: anonymize.New(anonymize.None),
		},
		{
			name: "success-simple-netblock",
			file: "valid-simple",
			anon: anonymize.New(anonymize.Netblock),
		},
		{
			name: "success-complex-netblock",
			file: "valid-complex",
			anon: anonymize.New(anonymize.Netblock),
		},
		{
			name: "success-complex-netblock-with-dst-in-hops-v6",
			file: "valid-complex-dst-in-hops-v6",
			anon: anonymize.New(anonymize.Netblock),
		},
		{
			name: "success-complex-netblock-with-dst-in-hops-v4",
			file: "valid-complex-dst-in-hops-v4",
			anon: anonymize.New(anonymize.Netblock),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := filepath.Join("./testdata/scamper2", tt.file)
			b, err := os.ReadFile(f)
			testingx.Must(t, err, "failed to read from file %s", tt.file)
			dp, err := (&scamper2Parser{}).ParseRawData(b)
			testingx.Must(t, err, "failed to parse raw data for %s", tt.file)

			s2 := dp.(*Scamper2)
			s2.AnonymizeHops(tt.anon)

			// After anonymization.
			dst := net.ParseIP(s2.Trace.Dst)
			h := s2.ExtractHops()
			for i := range h {
				hip := net.ParseIP(h[i])
				// Equal ips will contain themselves.
				if !dst.Equal(hip) && tt.anon.Contains(dst, hip) {
					t.Fatalf("hop IP within destination netblock after anonymization: %v contains %v", dst, hip)
				}
			}
		})
	}
}

func TestScamper2_MarshalJSONL(t *testing.T) {
	tests := []struct {
		name string
		file string
	}{
		{
			name: "success-simple",
			file: "valid-simple",
		},
		{
			name: "success-complex",
			file: "valid-complex",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := filepath.Join("./testdata/scamper2", tt.file)
			b, err := os.ReadFile(f)
			testingx.Must(t, err, "failed to read from file %s", tt.file)

			// Scamper generates JSON files with spaces after commas (i.e. ", ") while the Go encoder does not.
			// So, we have a three part sequence: parse, marshal, parse, marshal, compare.
			s, err := (&scamper2Parser{}).ParseRawData(b)
			testingx.Must(t, err, "failed to parse raw data for %s", tt.file)

			b2 := s.MarshalJSONL()
			s2, err := (&scamper2Parser{}).ParseRawData(b2)
			testingx.Must(t, err, "failed to parse marshaled data: %s", string(b2))

			b3 := s2.MarshalJSONL()
			if string(b2) != string(b3) {
				t.Errorf("Scamper2.MarshalJSONL() got %v, want %v", string(b3), string(b2))
			}
		})
	}
}
