package main

import (
	"context"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/resources"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/worker"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
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

type thresholdBudget struct {
	normal, protected                     bool
	normalCalls, protectedCalls, releases int
}

func (b *thresholdBudget) Try(int64) (func(), bool) {
	b.normalCalls++
	return func() { b.releases++ }, b.normal
}
func (b *thresholdBudget) TryProbe(int64) (func(), bool) {
	b.protectedCalls++
	return func() { b.releases++ }, b.protected
}

func TestSideAdmissionReadyDemandAcrossSlots(t *testing.T) {
	for _, tc := range []struct {
		name, prefix             string
		slot                     int
		active                   int32
		ready, normal, protected bool
		calls, checks, grants    int
	}{
		{"idle Side", "/side", 1, 0, false, false, true, 0, 1, 0},
		{"high slot carries first demand", "/side", 4, 0, true, false, true, 1, 1, 1},
		{"second active job", "/side", 3, 1, true, false, true, 1, 1, 1},
		{"two actual active jobs", "/side", 1, 2, true, false, true, 0, 0, 0},
		{"opportunistic third", "/side", 3, 2, true, true, true, 1, 0, 0},
		{"awaiting fair capacity", "/side", 2, 0, true, false, false, 0, 1, 1},
		{"ordinary keeps its permit", "", 4, 0, false, false, true, 1, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &thresholdBudget{normal: tc.normal, protected: tc.protected}
			var active atomic.Int32
			active.Store(tc.active)
			claims, checks := 0, 0
			c := client{prefix: tc.prefix, poll: &worker.PollGate{}, http: &http.Client{Transport: testTransport(func(r *http.Request) (*http.Response, error) {
				var body string
				switch r.URL.Path {
				case tc.prefix + "/ready":
					checks++
					body = strconv.FormatBool(tc.ready)
				case tc.prefix + "/claim":
					claims++
					body = `{"token":"fixture"}`
				default:
					t.Fatalf("unexpected method %s", r.URL.Path)
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
			})}}
			q := &admittedQueue{client: c, slot: tc.slot, maximum: 4, governor: &resources.Controller{Sensor: ampleMemory{}}, budget: b, active: &active}
			j, err := q.Claim(context.Background())
			if err != nil || claims != tc.calls || checks != tc.checks || b.protectedCalls != tc.grants {
				t.Fatalf("claims=%d checks=%d protected=%d err=%v", claims, checks, b.protectedCalls, err)
			}
			if (j != nil) != (tc.calls > 0) || active.Load() != tc.active+int32(tc.calls) {
				t.Fatal("active accounting diverged from leases")
			}
			if j != nil {
				q.release()
				if b.releases != 1 || active.Load() != tc.active {
					t.Fatal("release did not return capacity")
				}
			}
		})
	}
}

func TestPressuredSideClaimsPastFourWithoutDelayingOtherProcesses(t *testing.T) {
	var active atomic.Int32
	active.Store(9)
	b := &thresholdBudget{protected: true}
	ready := true
	c := client{prefix: "/side", poll: &worker.PollGate{}, http: &http.Client{Transport: testTransport(func(r *http.Request) (*http.Response, error) {
		response := strconv.FormatBool(ready)
		if r.URL.Path == "/side/claim" {
			response = `{"token":"leased"}`
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(response))}, nil
	})}}
	q := admittedQueue{client: c, slot: 10, maximum: 31, governor: &resources.Controller{Sensor: ampleMemory{}}, budget: b, active: &active}
	j, err := q.Claim(context.Background())
	if err != nil || j == nil || active.Load() != 10 || b.protectedCalls != 1 {
		t.Fatal(j, err, b)
	}
	q.release()
	active.Store(16)
	j, err = q.Claim(context.Background())
	if err != nil || j != nil || b.protectedCalls != 1 {
		t.Fatal("excess workers joined FIFO", j, err, b)
	}
}
