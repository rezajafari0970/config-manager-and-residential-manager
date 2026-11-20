package panel

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/collect"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/side"
)

func sidePass(t *testing.T, job *SideJob) SideResult {
	t.Helper()
	p := side.Prepare(job.Raw)
	if len(p.Candidates) == 0 || p.RawCandidate == nil {
		t.Fatalf("no fixture candidate: %s", p.Code)
	}
	c := p.Candidates[0]
	e := map[string]string{"raw_input_sha256": job.Hash, "raw_runtime_sha256": p.RawCandidate.SHA256, "raw_checks": "passed", "side_version": "side_v1", "warp_mode": "on", "candidate_sha256": c.SHA256,
		"upload_bytes": "131072", "download_bytes": "262144", "stability_samples": "3"}
	for _, k := range sideServices {
		e[k] = "passed"
	}
	return SideResult{Identity: job.Identity, Hash: job.Hash, Token: job.Token, Code: "passed", Candidate: c.Config, Evidence: e}
}
func sideClaim(t *testing.T, s *Store) *SideJob {
	t.Helper()
	j, err := s.ClaimSide(context.Background())
	if err != nil || j == nil || j.Issue != "" {
		t.Fatal("side claim", j == nil, err)
	}
	return j
}

func TestSideFreshAcquisitionOneGrantPerIdentityAndImmutablePositive(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	base := strings.Split(sourceURI(553), "#")[0]
	id, _ := newExportSource(t, s, "side-first", base+"#first")
	newExportSource(t, s, "side-second", base+"#second")
	var jobs [6]*SideJob
	var errs [6]error
	var wg sync.WaitGroup
	for i := range jobs {
		wg.Add(1)
		go func(i int) { defer wg.Done(); jobs[i], errs[i] = s.ClaimSide(ctx) }(i)
	}
	wg.Wait()
	var job *SideJob
	for i, c := range jobs {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		if c != nil {
			if job != nil {
				t.Fatal("duplicate concurrent grants")
			}
			job = c
		}
	}
	if job == nil || !bytes.Equal(job.Raw, []byte(base+"#first")) {
		t.Fatal("missing exact first representative")
	}
	full := sidePass(t, job)
	for _, k := range append(sideServices[:], "raw_checks", "raw_input_sha256", "raw_runtime_sha256", "warp_mode", "candidate_sha256", "upload_bytes", "download_bytes", "stability_samples") {
		old := full.Evidence[k]
		delete(full.Evidence, k)
		if err := s.CompleteSide(ctx, full); !errors.Is(err, ErrInvalid) {
			t.Fatalf("missing %s accepted: %v", k, err)
		}
		full.Evidence[k] = old
	}
	fake := full
	fake.Candidate = []byte(`{"outbounds":[]}`)
	full.Evidence["candidate_sha256"] = repair.Digest(fake.Candidate)
	if err := s.CompleteSide(ctx, fake); !errors.Is(err, ErrInvalid) {
		t.Fatal("unrelated candidate passed", err)
	}
	full.Evidence["candidate_sha256"] = repair.Digest(full.Candidate)
	for n := 0; n < 2; n++ {
		if err := s.CompleteSide(ctx, full); err != nil {
			t.Fatal("commit/replay", err)
		}
	}
	if stats, err := s.SideCounts(ctx); err != nil || stats.Accepted != 1 || stats.Template != 1 || stats.Pending+stats.Running != 0 {
		t.Fatal(stats, err)
	}
	// The live token, raw, template, and other config's receipt cannot substitute
	// for this input. Reacquisition after expiry cannot extend that first proof.
	if _, err := s.db.Exec("UPDATE side_jobs SET expires=1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(ctx, claimOne(t, s, id), acquisitionResult(t, s, base+"#renamed"), time.Now()); err != nil {
		t.Fatal(err)
	}
	if stats, err := s.SideCounts(ctx); err != nil || stats.Accepted != 0 || stats.Pending != 0 || stats.Expired != 1 {
		t.Fatal(stats, err)
	}
	if next, err := s.ClaimSide(ctx); err != nil || next != nil {
		t.Fatal("previous decision replayed", err)
	}
}

func TestSideInterruptedLeasesInfraAndFreshRejection(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	id, _ := newExportSource(t, s, "side-recover", sourceURI(671))
	stale := sideClaim(t, s)
	if _, err := s.db.Exec("UPDATE side_jobs SET lease_until=1"); err != nil {
		t.Fatal(err)
	}
	job := sideClaim(t, s)
	if stale.Token == job.Token {
		t.Fatal("lost lease reused")
	}
	if err := s.RenewSide(ctx, *stale); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if err := s.RenewSide(ctx, *job); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteSide(ctx, sidePass(t, stale)); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if err := s.DeferSide(ctx, *job, "side_driver_unavailable"); err != nil {
		t.Fatal(err)
	}
	if j, err := s.ClaimSide(ctx); err != nil || j != nil {
		t.Fatal("backoff skipped", err)
	}
	if _, err := s.db.Exec("UPDATE side_jobs SET next_run=0"); err != nil {
		t.Fatal(err)
	}
	job = sideClaim(t, s)
	if err := s.DeferSide(ctx, *job, "side_driver_unavailable"); err != nil {
		t.Fatal(err)
	}
	if stats, err := s.SideCounts(ctx); err != nil || stats.Inconclusive != 1 || stats.Rejected+stats.Pending != 0 {
		t.Fatal(stats, err)
	}
	fresh := sourceURI(672)
	if err := s.Complete(ctx, claimOne(t, s, id), acquisitionResult(t, s, sourceURI(671), fresh), time.Now()); err != nil {
		t.Fatal(err)
	}
	job = sideClaim(t, s)
	if !bytes.Equal(job.Raw, []byte(fresh)) {
		t.Fatal("incorrect new grant")
	}
	r := SideResult{Identity: job.Identity, Token: job.Token, Hash: job.Hash, Code: "side_checks_failed", Evidence: map[string]string{"warp": "warp_not_active"}}
	if err := s.CompleteSide(ctx, r); err != nil {
		t.Fatal(err)
	}
	if j, err := s.ClaimSide(ctx); err != nil || j != nil {
		t.Fatal("repeat", err)
	}
}

func TestSideAdministrativeRevocationFencesWorkerAcrossReenable(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	// The ordinary worker can be paused; the Side assessment is independent.
	if _, err := s.db.Exec("UPDATE conversion_settings SET enabled=0"); err != nil {
		t.Fatal(err)
	}
	a, _ := newExportSource(t, s, "side-admin-a", sourceURI(890))
	j := sideClaim(t, s)
	b, _ := newExportSource(t, s, "side-admin-b", sourceURI(890))
	source := func(id, action string) {
		t.Helper()
		v, err := s.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.ManageSources(ctx, SourceBatch{Action: action, Items: []SourceSelection{{ID: id, Revision: v.Revision}}}); err != nil {
			t.Fatal(err)
		}
	}
	source(a, "disable")
	if err := s.RenewSide(ctx, *j); err != nil {
		t.Fatal("shared live owner was revoked", err)
	}
	source(b, "disable")
	source(a, "enable")
	if err := s.CompleteSide(ctx, sidePass(t, j)); !errors.Is(err, ErrConflict) {
		t.Fatal("revoked grant accepted after re-enable", err)
	}
	fresh := sideClaim(t, s)
	r := sidePass(t, fresh)
	r.Code = "side_raw_failed"
	r.Evidence["raw_checks"] = "failed"
	r.Candidate = nil
	if err := s.CompleteSide(ctx, r); err != nil {
		t.Fatal("failed raw despite healthy template", err)
	}
	v, err := s.SideCounts(ctx)
	if err != nil || v.Rejected != 1 || v.Accepted+v.Pending != 0 {
		t.Fatal(v, err)
	}
}

func TestSideExpiredUnassessedNeedsNewReceipt(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	id, _ := newExportSource(t, s, "side-expiry", sourceURI(891))
	if _, err := s.db.Exec("UPDATE side_jobs SET expires=1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Expire(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, 1, "SELECT count(*) FROM side_jobs WHERE state='expired' AND code='retention_elapsed_before_assessment'")
	pendingCount(t, s.db, 0, "SELECT count(*) FROM side_sources")
	if j, err := s.ClaimSide(ctx); err != nil || j != nil {
		t.Fatal("unexpected history grant", err)
	}
	r := acquisitionResult(t, s, sourceURI(891))
	if err := s.Complete(ctx, claimOne(t, s, id), r, time.Now()); err != nil {
		t.Fatal(err)
	}
	j := sideClaim(t, s)
	if j.Identity != r.Items[0].Identity {
		t.Fatal("lost fresh input")
	}
}

func TestSideHeldValidatedResponseCanRunOnceBeforeMembership(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	id, err := s.Save(ctx, "", 0, testSource())
	if err != nil {
		t.Fatal(err)
	}
	large := cardinalityFixture(t, s, 32)
	if err = s.Complete(ctx, claimOne(t, s, id), large, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Freeze ordinary candidates to focus the claim on the held source input.
	if _, err = s.db.Exec("UPDATE side_jobs SET next_run=?", time.Now().Add(time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	held := acquisitionResult(t, s, sourceURI(899))
	j := claimOne(t, s, id)
	for _, item := range held.Items {
		if _, err = s.Stage(ctx, j, item); err != nil {
			t.Fatal(err)
		}
	}
	held.Staged = true
	held.Items = nil
	if err = s.Complete(ctx, j, held, time.Now()); err != nil {
		t.Fatal(err)
	}
	c := sideClaim(t, s)
	if err = s.CompleteSide(ctx, sidePass(t, c)); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, 0, "SELECT count(*) FROM side_export_inputs")
	pendingCount(t, s.db, 1, "SELECT count(*) FROM side_jobs WHERE identity=? AND state='accepted'", c.Identity)
	if j, err := s.ClaimSide(ctx); err != nil || j != nil {
		t.Fatal("duplicate held grant", err)
	}
}

func TestSideInfrastructureRecoveryRequiresNewBytesAfterObservedRecoveryAndIsBounded(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	a, _ := newExportSource(t, s, "side-once-repair", sourceURI(911))
	j := sideClaim(t, s)
	if _, err := s.db.Exec("UPDATE side_jobs SET attempts=3 WHERE identity=?", j.Identity); err != nil {
		t.Fatal(err)
	}
	if err := s.DeferSide(ctx, *j, "side_provider_unavailable"); err != nil {
		t.Fatal(err)
	}
	refetch := func() {
		t.Helper()
		if err := s.Complete(ctx, claimOne(t, s, a), acquisitionResult(t, s, sourceURI(911)), time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	refetch()
	pendingCount(t, s.db, 1, "SELECT count(*) FROM side_jobs WHERE state='inconclusive' AND repairs=0")
	newExportSource(t, s, "side-observed-repair", sourceURI(912))
	healthy := sideClaim(t, s)
	if err := s.CompleteSide(ctx, sidePass(t, healthy)); err != nil {
		t.Fatal(err)
	}
	// A valid 304 confirms ownership; it cannot spend the final recovery grant.
	if err := s.Complete(ctx, claimOne(t, s, a), collect.Result{State: "unchanged", HTTPStatus: 304}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if v, err := s.ClaimSide(ctx); err != nil || v != nil {
		t.Fatal("304 reactivated unresolved", err)
	}
	refetch()
	recovered := sideClaim(t, s)
	if recovered.Identity != j.Identity {
		t.Fatal("recovered wrong identity")
	}
	if err := s.DeferSide(ctx, *recovered, "side_provider_unavailable"); err != nil {
		t.Fatal(err)
	}
	refetch()
	pendingCount(t, s.db, 1, "SELECT count(*) FROM side_jobs WHERE state='inconclusive' AND repairs=1")
	if v, err := s.ClaimSide(ctx); err != nil || v != nil {
		t.Fatal("unbounded recovery", err)
	}
}

func TestSideWaitStartsAtQueueAdmission(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	start := time.Now().UnixMilli()
	id, _ := newExportSource(t, s, "existing-source", sourceURI(51))
	// Reproduce a first Side admission of a still-valid source artifact that
	// predates this feature. Its ordinary retention clock must be preserved.
	if _, err := s.db.Exec(`DELETE FROM side_jobs; UPDATE artifacts SET created=created-3600000;
		INSERT INTO side_receipts SELECT m.source_id,m.artifact_id,m.raw_hash,m.kind,m.size,a.created,a.expires,0
		FROM memberships m JOIN artifacts a ON a.id=m.artifact_id WHERE m.source_id=?`, id); err != nil {
		t.Fatal(err)
	}
	counts, err := s.SideCounts(ctx)
	if err != nil || counts.Pending != 1 || counts.OldestPending < start {
		t.Fatalf("wait includes time before feature admission: %+v, %v", counts, err)
	}
	if _, err := s.db.Exec("UPDATE side_jobs SET queued_at=queued_at-3000"); err != nil {
		t.Fatal(err)
	}
	commitProbeInputs(t, s, id, sourceURI(51))
	refetched, err := s.SideCounts(ctx)
	if err != nil || refetched.OldestPending != counts.OldestPending-3000 {
		t.Fatal("repeat fetch reset waiting time", err)
	}
}
