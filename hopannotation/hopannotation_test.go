package hopannotation_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/m-lab/traceroute-caller/hopannotation"
	"github.com/m-lab/uuid-annotator/annotator"
)

var (
	invalidIP    = "invalid IP address"
	errInvalidIP = errors.New(invalidIP)
)

type fakeIPServiceClient struct {
	calls int32
}

func (f *fakeIPServiceClient) Annotate(ctx context.Context, hops []string) (map[string]*annotator.ClientAnnotations, error) {
	atomic.AddInt32(&f.calls, 1)
	m := make(map[string]*annotator.ClientAnnotations)
	for _, hop := range hops {
		m[hop] = &annotator.ClientAnnotations{}
	}
	return m, nil
}

var fakeArchiveHopAnnotationCalls int32

func fakeArchiveHopAnnotation(ctx context.Context, hop string, annotation *annotator.ClientAnnotations) error {
	atomic.AddInt32(&fakeArchiveHopAnnotationCalls, 1)
	return nil
}

func TestAnnotateArchive(t *testing.T) {
	tests := []struct {
		input   []string
		wantN   int
		wantK   int
		wantErr error
	}{
		{[]string{"1.2.3.4", "5.6.7.8"}, 2, 2, nil},
		{[]string{"1.2.3.4", "5.6.7.8"}, 0, 0, nil},
		// Clear the cache before the next test.
		{[]string{"1.2.3.4", "5.6.7.8"}, 2, 2, nil},
		{[]string{"5.6.7.8", "a:b:c:d::e"}, 1, 1, nil},
		{[]string{"1.2.3"}, 0, 0, errInvalidIP},
	}

	saveHopArchiver := hopannotation.HopArchiver
	hopannotation.HopArchiver = fakeArchiveHopAnnotation
	defer func() {
		hopannotation.HopArchiver = saveHopArchiver
	}()
	ipServiceClient := &fakeIPServiceClient{}
	hc := hopannotation.New(ipServiceClient, "./local")
	for i, test := range tests {
		wantN, wantK, wantErr := test.wantN, test.wantK, test.wantErr
		gotN, gotK, gotErr := hc.AnnotateArchive(context.TODO(), test.input, time.Now())
		failed := false
		if gotN != wantN || gotK != wantK {
			failed = true
		}
		if wantErr == nil {
			if gotErr != nil {
				failed = true
			}
		} else if gotErr == nil || gotErr.Error() != wantErr.Error() {
			failed = true
		}
		if failed {
			t.Errorf("hc.AnnotateArchive() = %v/%v/%v, want: %v/%v/%v", gotN, gotK, gotErr, wantN, wantK, wantErr)
		}
		if i == 1 {
			hc.Clear()
		}
	}
	// There are 4 valid rows in tests.
	if ipServiceClient.calls != 4 {
		t.Errorf("got %d calls to Annotate(), want 4", ipServiceClient.calls)
	}
	// There are 2+2+1 *new* addresses in tests.
	if fakeArchiveHopAnnotationCalls != 5 {
		t.Errorf("got %d calls to fakeArchiveHopAnnotation(), want 5", fakeArchiveHopAnnotationCalls)
	}
}
