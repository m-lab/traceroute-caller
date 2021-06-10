package main

import (
	"context"
	"log"
	"testing"

	"github.com/m-lab/uuid-annotator/annotator"
)

// Implementation
// TODO add a test that actually uses this?
func hopGen(ctx context.Context, ip string, ann *annotator.ClientAnnotations) error {
	log.Println("Pretend we wrote a file for", ip)
	return nil
}

type fake struct {
}

func (ann fake) Annotate(ctx context.Context, ips []string) (map[string]*annotator.ClientAnnotations, error) {
	result := make(map[string]*annotator.ClientAnnotations, len(ips))
	for _, ip := range ips {
		result[ip] = &annotator.ClientAnnotations{}
	}
	return result, nil
}

func TestHopCache(t *testing.T) {
	hc := New(&fake{}, hopGen)
	n, k, err := hc.AnnotateNewHops(context.TODO(), []string{"1.2.3.4", "5.6.7.8"})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(n, k)
	n, k, err = hc.AnnotateNewHops(context.TODO(), []string{"5.6.7.8", "foo:bar"})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(n, k)
	hc.Clear()
	n, k, err = hc.AnnotateNewHops(context.TODO(), []string{"5.6.7.8", "foo:bar"})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(n, k)
}

// TODO add a complex multithreaded test
