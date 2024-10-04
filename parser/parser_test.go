package parser

import (
	"log"
	"strings"
	"testing"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func TestNew(t *testing.T) {
	tests := []struct {
		traceType string
		wantErr   error
	}{
		{"mda", nil},
		{"regular", nil},
		{"", ErrTracerouteType},
		{"bad", ErrTracerouteType},
	}
	for _, test := range tests {
		_, gotErr := New(test.traceType, "jsonl")
		if badErr(gotErr, test.wantErr) {
			t.Fatalf("New() = %v, want %v", gotErr, test.wantErr)
		}
	}
}

func badErr(gotErr, wantErr error) bool {
	if gotErr == nil {
		return wantErr != nil
	}
	if strings.Contains(gotErr.Error(), wantErr.Error()) {
		return false
	}
	return true
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
