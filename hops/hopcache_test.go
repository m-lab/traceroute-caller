package hops_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/m-lab/traceroute-caller/hops"
	"github.com/m-lab/uuid-annotator/annotator"
)

// This is a fake implementation of the hop record generator.
// It counts number of alls, and can return a series of errors.
type fakeGen struct {
	err   chan error // list of errors to return
	calls int32      // number of times called
}

func (g *fakeGen) hopGen(ctx context.Context, ip string, ann *annotator.ClientAnnotations) error {
	atomic.AddInt32(&g.calls, 1)
	select {
	case e := <-g.err:
		return e
	default:
		log.Println("Pretend we wrote a file for", ip)
	}
	return nil
}

type fake struct{}

func (ann fake) Annotate(ctx context.Context, ips []string) (map[string]*annotator.ClientAnnotations, error) {
	result := make(map[string]*annotator.ClientAnnotations, len(ips))
	for _, ip := range ips {
		result[ip] = &annotator.ClientAnnotations{}
	}
	return result, nil
}

func expect(t *testing.T, ips []string, hc hops.Cache, nn, kk int) {
	t.Helper()
	n, k, _ := hc.AnnotateNewHops(context.TODO(), ips)

	if n != nn || k != kk {
		t.Errorf("req: %d/%d, actual: %d/%d\n", n, nn, k, kk)
	}
}

func TestHopCache(t *testing.T) {
	gen := fakeGen{err: make(chan error, 10)}
	hc := hops.New(&fake{}, gen.hopGen)

	expect(t, []string{"1.2.3.4", "5.6.7.8"}, hc, 2, 2)
	expect(t, []string{"1.2.3.4", "5.6.7.8"}, hc, 0, 0)
	hc.Clear()
	expect(t, []string{"1.2.3.4", "5.6.7.8"}, hc, 2, 2)
	expect(t, []string{"5.6.7.8", "a:b:c:d::e"}, hc, 1, 1)

	gen.err <- errors.New("error")
	expect(t, []string{"error"}, hc, 1, 0)
	if gen.calls != 6 {
		t.Error(gen.calls)
	}
}

func TestConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	gen := fakeGen{err: make(chan error, 10)}
	hc := hops.New(&fake{}, gen.hopGen)

	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func(n int) {
			// Altogether, these will post all values from 0 to 1004, about 300,000 times
			// each in semi-random order.
			for j := 0; j < 100; j++ {
				time.Sleep(time.Duration(rand.Int31n(1000000)))
				hc.AnnotateNewHops(context.TODO(),
					[]string{fmt.Sprint(n + j%3), fmt.Sprint(n + j%4), fmt.Sprint(n + j%5)})
			}
			wg.Done()
		}(i)
	}
	wg.Wait()

	calls := atomic.LoadInt32(&gen.calls)
	if calls != 1004 {
		t.Error("Should have been exactly 1004 calls to generator", calls)
	}
}

// BenchmarkConcurrent-4   	   36865	     45702 ns/op	    1748 B/op	      81 allocs/op
// 45 microseconds to make 10 calls with 3 ips each, with massive contention (37K goroutines).
// Total of about 37K cache entries, 1M ips, in about 1.6 seconds?
func BenchmarkConcurrent(b *testing.B) {
	var wg sync.WaitGroup
	start := make(chan struct{})

	gen := func(ctx context.Context, ip string, ann *annotator.ClientAnnotations) error {
		return nil
	}
	hc := hops.New(&fake{}, gen)

	b.StopTimer()
	for i := 0; i < b.N; i++ {
		wg.Add(1)
		go func(n int) {
			<-start
			// Altogether, these will post all values from 0 to b.N+4, about 30 times,
			// in pseudo-random order.
			for j := 0; j < 10; j++ {
				//time.Sleep(time.Duration(rand.Int31n(1000)))
				hc.AnnotateNewHops(context.TODO(),
					[]string{fmt.Sprint(n + j%3), fmt.Sprint(n + j%4), fmt.Sprint(n + j%5)})
			}
			wg.Done()
		}(i)
	}

	time.Sleep(10 * time.Millisecond)
	b.StartTimer()
	close(start)
	wg.Wait()
}
