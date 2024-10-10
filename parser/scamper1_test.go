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
		{"valid-complex", nil, []string{
			"2001:4888:36:1002:3a2:1:0:1",
			"2001:550:1b01:1::1",
			"2001:550:3::1ca",
			"2001:4888:3f:6092:3a2:26:0:1",
			"2600:803::79",
			"2600:803:150f::4a"},
		},
		{"valid-star", nil, []string{}}, // all "addr" values are either "*" or ""
	}
	for _, test := range tests {
		t.Run(test.file, func(t *testing.T) {
			// Read in the test traceroute output file.
			f := filepath.Join("./testdata/scamper1", test.file)
			content, err := os.ReadFile(f)
			if err != nil {
				t.Fatalf(err.Error())
			}

			// Extract start_time from the cycle-start line.
			p, err := New("mda", "jsonl")
			if p.Format() != "jsonl" {
				t.Errorf("Format wrong; got %q, want jsonl", p.Format())
			}
			testingx.Must(t, err, "failed to get new parser")
			scamperOutput, gotErr := p.ParseRawData(content)
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

func TestScamper1_Anonymize(t *testing.T) {

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
			f := filepath.Join("./testdata/scamper1", tt.file)
			b, err := os.ReadFile(f)
			testingx.Must(t, err, "failed to read from file %s", tt.file)
			dp, err := (&scamper1Parser{}).ParseRawData(b)
			testingx.Must(t, err, "failed to parse raw data for %s", tt.file)

			s1 := dp.(*Scamper1)
			s1.Anonymize(tt.anon)

			// After anonymization.
			dst := net.ParseIP(s1.Tracelb.Dst)
			h := s1.ExtractHops()
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

func TestScamper1_MarshalAsJSONL(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		as      string
		wantErr bool
	}{
		{
			name: "success-simple",
			file: "valid-simple",
			as:   "jsonl",
		},
		{
			name: "success-complex",
			file: "valid-complex",
			as:   "jsonl",
		},
		{
			name:    "invalid-format",
			file:    "valid-simple",
			as:      "tgz",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := filepath.Join("./testdata/scamper1", tt.file)
			b, err := os.ReadFile(f)
			testingx.Must(t, err, "failed to read from file %s", tt.file)

			// Scamper generates JSON files with spaces after commas (i.e. ", ") while the Go encoder does not.
			// So, we have a three part sequence: parse, marshal, parse, marshal, compare.
			s1, err := (&scamper1Parser{format: tt.as}).ParseRawData(b)
			testingx.Must(t, err, "failed to parse raw data for %s", tt.file)

			b2, err := s1.Marshal(tt.as)
			if tt.wantErr && (err == nil) {
				t.Errorf("failed to marshal data for %s", tt.file)
			}
			if tt.wantErr {
				return
			}

			s2, err := (&scamper1Parser{}).ParseRawData(b2)
			testingx.Must(t, err, "failed to parse marshaled data: %s", string(b2))

			b3, err := s2.Marshal(tt.as)
			testingx.Must(t, err, "failed to marshal data")
			if string(b2) != string(b3) {
				t.Errorf("Scamper1.MarshalAsJSONL() got %v, want %v", string(b3), string(b2))
			}
		})
	}
}

func TestScamper1_MarshalAsJSON(t *testing.T) {
	f := filepath.Join("./testdata/scamper1/valid-simple")
	b, err := os.ReadFile(f)
	testingx.Must(t, err, "failed to read from file")

	s2, err := (&scamper1Parser{}).ParseRawData(b)
	testingx.Must(t, err, "failed to parse marshaled data: %s", string(b))

	_, err = s2.Marshal("json")
	if err == nil {
		t.Errorf("failed to generate error for unsupported type")
	}
}
