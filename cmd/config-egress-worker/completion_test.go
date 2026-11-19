package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

type receiptTransport func(*http.Request) (*http.Response, error)

func (f receiptTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestLeaseWritesReplayExactPayload(t *testing.T) {
	for _, tc := range []struct {
		name     string
		path     string
		statuses []int
		want     int
	}{
		{"heartbeat-outage", "renew", []int{503, 200}, 200},
		{"service-unavailable", "complete", []int{503, 200}, 200},
		{"connection-lost", "complete", []int{0, 200}, 200},
		{"lost-acknowledgment-or-expired-lease", "complete", []int{0, 409}, 409},
		{"revoked-lease", "complete", []int{409}, 409},
		{"invalid-report", "complete", []int{400}, 400},
		{"persistent-outage", "complete", []int{503, 503, 503}, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			receipt := egress.Completion{
				Job:    egress.Job{Hash: "identity", Revision: 7, Token: "fixture"},
				Report: egress.Report{Hash: "identity", Version: egress.Version, Started: 10, Finished: 100},
			}
			calls := 0
			var original []byte
			c := client{&http.Client{Transport: receiptTransport(func(r *http.Request) (*http.Response, error) {
				if calls >= len(tc.statuses) || r.URL.Path != "/egress/"+tc.path {
					t.Fatalf("unexpected call %d to %s", calls, r.URL.Path)
				}
				body, err := io.ReadAll(r.Body)
				r.Body.Close()
				if err != nil || len(body) == 0 {
					t.Fatalf("missing receipt: %v", err)
				}
				if calls == 0 {
					original = body
				} else if !bytes.Equal(body, original) {
					t.Fatal("replayed a different receipt")
				}
				status := tc.statuses[calls]
				calls++
				if status == 0 {
					return nil, io.ErrUnexpectedEOF
				}
				return &http.Response{StatusCode: status, Body: http.NoBody}, nil
			})}}
			var payload any = receipt
			if tc.path == "renew" {
				payload = receipt.Job
			}
			err := c.sendLeased(context.Background(), tc.path, payload)
			if calls != len(tc.statuses) {
				t.Fatalf("sent %d times, want %d", calls, len(tc.statuses))
			}
			var status apiStatus
			if tc.want == 200 {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.As(err, &status) || int(status) != tc.want {
				t.Fatalf("wanted HTTP %d, got %v", tc.want, err)
			}
		})
	}
}
