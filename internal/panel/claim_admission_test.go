package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func TestClaimAdmissionKeepsSingleExportAndWriterAvailable(t *testing.T) {
	s := testStore(t)
	seedRotation(t, s, 61, 2)
	ctx := context.Background()
	// Prepare a real output round before simulating one slow background claim.
	if next, err := s.prepareRotation(ctx); err != nil || next == nil {
		t.Fatal(next, err)
	}
	release, err := s.admitClaim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	claims := map[string]func(context.Context) error{
		"ordinary": func(ctx context.Context) error { _, err := s.ClaimProbe(ctx); return err },
		"initial":  func(ctx context.Context) error { _, err := s.ClaimEgressLane(ctx, "initial"); return err },
		"followup": func(ctx context.Context) error { _, err := s.ClaimEgressLane(ctx, "followup"); return err },
	}
	before := s.db.Stats()
	for name, claim := range claims {
		t.Run(name, func(t *testing.T) {
			limited, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
			defer cancel()
			if err := claim(limited); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("claim bypassed shared admission", err)
			}
		})
	}
	if after := s.db.Stats(); after.WaitCount != before.WaitCount || after.InUse != 0 {
		t.Fatal("waiting claims reached writer", before, after)
	}
	limited, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.Ping(limited); err != nil {
		t.Fatal("database watchdog blocked behind admission", err)
	}
	if next, err := s.NextConversion(limited); err != nil || next == nil || len(next.Bytes) == 0 {
		t.Fatal("single export blocked behind admission", next, err)
	}
	release()
	// Cancellation must not leak admission or invalidate normal lease recovery.
	if _, err := s.ClaimProbe(limited); err != nil {
		t.Fatal("ordinary claim did not recover", err)
	}
	if _, err := s.ClaimEgressLane(limited, "initial"); err != nil {
		t.Fatal("egress claim did not recover", err)
	}
}

func privateWorkerPost(h http.Handler, ctx context.Context, path string, body []byte) <-chan int {
	result := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body)).WithContext(ctx))
		result <- w.Code
	}()
	return result
}

func TestPrivateClaimsLeaveWriterAvailableWhileRanking(t *testing.T) {
	s := testStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	newExportSource(t, s, "admission", sourceURI(973), sourceURI(974))
	j, err := s.ClaimEgress(ctx)
	if err != nil || j == nil {
		t.Fatal("fixture claim", err)
	}
	report, err := json.Marshal(egress.Completion{Job: *j, Report: syntheticEgress(*j)})
	if err != nil {
		t.Fatal(err)
	}

	// Occupy the WAL reader to pause a real claim after it has acquired its
	// claim slot and before it can enter the writer transaction.
	reader := s.workerReader()
	reader.SetMaxOpenConns(1)
	block, err := reader.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer block.Close()
	before := reader.Stats().WaitCount
	h := s.PrivateProbeHandler()
	laneCtx, cancelRank := context.WithCancel(ctx)
	defer cancelRank()
	rank := privateWorkerPost(h, laneCtx, "/egress/%63laim", []byte(`{"lane":"initial"}`))
	for reader.Stats().WaitCount == before {
		if ctx.Err() != nil {
			t.Fatal("claim never reached WAL reader", ctx.Err())
		}
		time.Sleep(time.Millisecond)
	}
	ordinary := privateWorkerPost(h, ctx, "/claim", nil)
	for _, call := range []struct {
		path string
		body []byte
	}{
		{"/egress/status", []byte(`{"status":"running","active":1,"code":"ready"}`)},
		{"/egress/complete", report},
	} {
		if code := <-privateWorkerPost(h, ctx, call.path, call.body); code != http.StatusOK {
			t.Fatal("unrelated worker blocked by rank", call.path, code)
		}
	}
	if err = s.Ping(ctx); err != nil {
		t.Fatal("foreground blocked by rank", err)
	}
	cancelRank()
	if code := <-rank; code == http.StatusOK {
		t.Fatal("cancelled rank completed")
	}
	if code := <-ordinary; code != http.StatusOK {
		t.Fatal("ordinary claim retained writer while waiting", code)
	}
	if err = block.Close(); err != nil {
		t.Fatal(err)
	}
	if code := <-privateWorkerPost(h, ctx, "/egress/claim", []byte(`{}`)); code != http.StatusOK {
		t.Fatal("claim slot leaked", code)
	}
}

func TestPrivateClaimWriterAdmissionCancellation(t *testing.T) {
	s := testStore(t)
	newExportSource(t, s, "claimadmission", sourceURI(975))
	h := s.PrivateProbeHandler()
	for _, path := range []string{"/egress/claim", "/%63laim"} {
		t.Run(path, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			release, err := s.operations.acquire(ctx, true)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			before := s.db.Stats().WaitCount
			jobCtx, cancelJob := context.WithCancel(ctx)
			defer cancelJob()
			result := privateWorkerPost(h, jobCtx, path, []byte(`{}`))
			waitAdmission(t, &s.operations, 0, 1)
			if len(s.claimSlot) != 1 {
				t.Fatal("writer admission acquired before claim slot")
			}
			cancelJob()
			if code := <-result; code == http.StatusOK {
				t.Fatal("cancelled job acquired lease")
			}
			if s.db.Stats().WaitCount != before || len(s.claimSlot) != 0 {
				t.Fatal("claim bypassed writer admission or leaked slot")
			}
			waitAdmission(t, &s.operations, 0, 0)
			pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_jobs WHERE token!=''")
		})
	}
}
