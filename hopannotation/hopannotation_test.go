package hopannotation_test

import (
	"context"
	"errors"
	"io/fs"
	"sync/atomic"
	"testing"
	"time"

	"github.com/m-lab/traceroute-caller/hopannotation"
	"github.com/m-lab/uuid-annotator/annotator"
)

var (
	invalidIP    = "failed to parse hop IP address: 1.2.3"
	errInvalidIP = errors.New(invalidIP)

	fakeWriteFileCalls int32
)

type fakeIPServiceClient struct {
	annotateCalls int32
}

func (f *fakeIPServiceClient) Annotate(ctx context.Context, hops []string) (map[string]*annotator.ClientAnnotations, error) {
	atomic.AddInt32(&f.annotateCalls, 1)
	m := make(map[string]*annotator.ClientAnnotations)
	for _, hop := range hops {
		m[hop] = &annotator.ClientAnnotations{}
	}
	return m, nil
}

func fakeWriteFile(filename string, data []byte, perm fs.FileMode) error {
	atomic.AddInt32(&fakeWriteFileCalls, 1)
	return nil
}

func TestAnnotateArchive(t *testing.T) {
	tests := []struct {
		input          []string
		wantAllErrs    []error
		annotateCalls  int32
		writeFileCalls int32
	}{
		{[]string{"1.2.3.4", "5.6.7.8"}, nil, 1, 2}, // should annotate and archive both
		{[]string{"1.2.3.4", "5.6.7.8"}, nil, 1, 2}, // should not annotate and archive either
		// Clear the cache before the next test.
		{[]string{"1.2.3.4", "5.6.7.8"}, nil, 2, 4},      // should annotate and archive both
		{[]string{"5.6.7.8", "a:b:c:d::e"}, nil, 3, 5},   // should annotate and archive just one
		{[]string{"1.2.3"}, []error{errInvalidIP}, 3, 5}, // should return error
	}

	// Mock WriteFile.
	saveWriteFile := hopannotation.WriteFile
	hopannotation.WriteFile = fakeWriteFile
	defer func() {
		hopannotation.WriteFile = saveWriteFile
	}()

	ipServiceClient := &fakeIPServiceClient{}
	hc := hopannotation.New(ipServiceClient, "./local")
	for i, test := range tests {
		if i == 2 {
			hc.Clear()
		}
		gotAllErrs := hc.AnnotateArchive(context.TODO(), test.input, time.Now())

		// Verify that we got the right errors, if any.
		failed := false
		if len(gotAllErrs) != len(test.wantAllErrs) {
			failed = true
		} else {
			for i := range gotAllErrs {
				if gotAllErrs[i].Error() != test.wantAllErrs[i].Error() {
					failed = true
				}
			}
		}
		if failed {
			t.Errorf("hc.AnnotateArchive() = %+v, want: %+v", gotAllErrs, test.wantAllErrs)
		}

		// Verify the number of annotate calls.
		if ipServiceClient.annotateCalls != test.annotateCalls {
			t.Errorf("got %d annotate calls, want %d", ipServiceClient.annotateCalls, test.annotateCalls)
		}

		// Verify the number of WriteFile calls.
		if fakeWriteFileCalls != test.writeFileCalls {
			t.Errorf("got %d WriteFile calls, want %d", fakeWriteFileCalls, test.writeFileCalls)
		}
	}
}
