package main

import (
	"context"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/resources"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/worker"
	"io"
	"net/http"
	"strings"
	"testing"
)

type testTransport func(*http.Request) (*http.Response, error)

func (f testTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type lowMemory struct{}

func (lowMemory) Sample() resources.Sample { return resources.Sample{AvailableKB: 100} }
func TestPressureAndEmptyPollDoNotClaimOrLoseLeases(t *testing.T) {
	calls := 0
	c := client{poll: &worker.PollGate{}, http: &http.Client{Transport: testTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("null")), Header: make(http.Header)}, nil
	})}}
	q := admittedQueue{client: c, slot: 1, maximum: 8, governor: &resources.Controller{Sensor: lowMemory{}}}
	if j, e := q.Claim(context.Background()); e != nil || j != nil || calls != 0 {
		t.Fatal("pressure created lease", j, e, calls)
	}
	for i := 0; i < 8; i++ {
		if j, e := c.Claim(context.Background()); e != nil || j != nil {
			t.Fatal(j, e)
		}
	}
	if calls != 1 {
		t.Fatal("idle slots queried separately", calls)
	}
	// Critical renewal/completion calls deliberately bypass the idle gate.
	if e := c.call(context.Background(), "/renew", nil, nil); e != nil || calls != 2 {
		t.Fatal("renewal blocked", e, calls)
	}
}

type ampleMemory struct{}

func (ampleMemory) Sample() resources.Sample {
	return resources.Sample{AvailableKB: 8 * 1024 * 1024, CPUValid: true, IOValid: true}
}

type recordingBudget struct{ calls, releases int }

func (b *recordingBudget) Try(int64) (func(), bool) { b.calls++; return func() { b.releases++ }, true }
func TestIdleGatePrecedesReservationAndEmptyClaimReleases(t *testing.T) {
	b := &recordingBudget{}
	gate := &worker.PollGate{}
	c := client{poll: gate, http: &http.Client{Transport: testTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("null")), Header: make(http.Header)}, nil
	})}}
	q := admittedQueue{client: c, slot: 1, maximum: 8, governor: &resources.Controller{Sensor: ampleMemory{}}, budget: b}
	if _, e := q.Claim(context.Background()); e != nil {
		t.Fatal(e)
	}
	for n := 0; n < 20; n++ {
		q.Claim(context.Background())
	}
	if b.calls != 1 || b.releases != 1 {
		t.Fatal("idle polling reserved memory", b)
	}
}
