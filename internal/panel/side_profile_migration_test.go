package panel

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
)

func TestSideV57RepairsOnlyCurrentIncompleteProfilesOnce(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	const partial = `{"side_version":"side_v1","warp_mode":"off","warp":"warp_not_active","google":"not_run"}`
	exec := func(statement string, args ...any) {
		t.Helper()
		if _, err := s.db.Exec(statement, args...); err != nil {
			t.Fatal(err)
		}
	}
	raw := sourceURI(31)
	original, _ := newExportSource(t, s, "original", raw)
	alias, _ := newExportSource(t, s, "alias", raw+"#new-label")
	newExportSource(t, s, "unaffected", sourceURI(32), sourceURI(33), sourceURI(34), sourceURI(35), sourceURI(36))
	inactive, _ := newExportSource(t, s, "disabled", sourceURI(37))
	newExportSource(t, s, "already-accepted", sourceURI(38))
	// Store real complete v2 results and then reconstruct the old version's
	// partial receipts at the persistence boundary. An identity present under
	// a differently named URI survives after its original source is removed.
	for i := 31; i <= 38; i++ {
		j := sideClaim(t, s)
		r := sideReject(t, j)
		if j.Hash == repair.Digest([]byte(sourceURI(38))) {
			r = sidePass(t, j)
		}
		if err := s.CompleteSide(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	exec("UPDATE side_jobs SET evidence=?,finished=123 WHERE state='rejected' AND raw_hash!=?", partial, repair.Digest([]byte(sourceURI(32))))
	exec("UPDATE side_jobs SET evidence=json_set(evidence,'$.side_version','side_v1') WHERE raw_hash=?", repair.Digest([]byte(sourceURI(32))))
	exec("UPDATE side_jobs SET expires=1 WHERE raw_hash=?", repair.Digest([]byte(sourceURI(33))))
	exec("UPDATE side_jobs SET evidence='{}',code='client_core_incompatible' WHERE raw_hash=?", repair.Digest([]byte(sourceURI(34))))
	exec("INSERT INTO config_controls SELECT identity,'disabled',0,expires FROM side_jobs WHERE raw_hash=?", repair.Digest([]byte(sourceURI(35))))
	exec("UPDATE memberships SET generation=generation-1 WHERE raw_hash=?", repair.Digest([]byte(sourceURI(36))))
	exec("UPDATE sources SET enabled=0 WHERE id=?", inactive)
	exec("DELETE FROM sources WHERE id=?", original)
	exec("DROP TABLE side_partial_receipts; PRAGMA user_version=56")
	if err := s.migrateV57(); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, 1, "SELECT count(*) FROM side_partial_receipts WHERE raw_hash=? AND evidence=? AND finished=123",
		repair.Digest([]byte(raw)), partial)
	pendingCount(t, s.db, 1, "SELECT count(*) FROM side_sources WHERE source_id=? AND identity IN(SELECT identity FROM side_partial_receipts)", alias)
	pendingCount(t, s.db, 1, "SELECT count(*) FROM side_jobs WHERE state='pending' AND code='side_profile_completion'")
	j := sideClaim(t, s)
	if string(j.Raw) != raw+"#new-label" {
		t.Fatal("unowned original bytes used instead of current alias")
	}
	r := sideReject(t, j)
	if err := s.CompleteSide(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := s.migrateV57(); err != nil {
		t.Fatal(err)
	}
	fillExportSource(t, s, alias, raw+"#another-label")
	if n, err := s.ClaimSide(ctx); err != nil || n != nil {
		t.Fatal("replayed repaired, expired, inactive or complete profile", err)
	}
	pendingCount(t, s.db, 1, "SELECT count(*) FROM side_jobs WHERE state='accepted'")
	pendingCount(t, s.db, 1, "SELECT count(*) FROM side_partial_receipts")
}

func TestSideV57RequiresEveryRunnableGateAndRetainsInfrastructureObservation(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	newExportSource(t, s, "integrity-check", sourceURI(51))
	j := sideClaim(t, s)
	r := sideReject(t, j)
	for _, key := range sideServices {
		value := r.Evidence[key]
		r.Evidence[key] = "not_run"
		if err := s.CompleteSide(ctx, r); !errors.Is(err, ErrInvalid) {
			t.Fatalf("missing gate %s was terminal: %v", key, err)
		}
		r.Evidence[key] = value
	}
	rawFailure := sidePass(t, j)
	rawFailure.Candidate = nil
	rawFailure.Code = "side_checks_failed"
	rawFailure.Evidence["raw_checks"] = "failed"
	rawFailure.Evidence["raw_failure"] = "side_checks_failed"
	for _, gate := range sideServices {
		rawFailure.Evidence["raw_"+gate] = "passed"
	}
	rawFailure.Evidence["raw_warp"] = "warp_not_active"
	if !validSideEvidence(rawFailure) {
		t.Fatal("complete distinct raw profile invalid")
	}
	delete(rawFailure.Evidence, "raw_upload")
	if validSideEvidence(rawFailure) {
		t.Fatal("incomplete raw session recorded as fully checked")
	}
	importFailure := sidePass(t, j)
	importFailure.Candidate = nil
	importFailure.Code = "app_transform_core_rejected"
	importFailure.Evidence["app_import_contract"] = "failed"
	delete(importFailure.Evidence, "raw_checks")
	if !validSideEvidence(importFailure) {
		t.Fatal("ten measured gates followed by real import rejection invalid")
	}
	// A local driver fault does not prove rejection. The final unsuccessful
	// attempt remains visible with its service observations.
	r.Evidence["upload"] = "side_driver_unavailable"
	if err := s.CompleteSide(ctx, r); !errors.Is(err, ErrInvalid) {
		t.Fatal("local launch failure recorded as a completed measurement", err)
	}
	if _, err := s.db.Exec("UPDATE side_jobs SET attempts=?", sideAttempts); err != nil {
		t.Fatal(err)
	}
	if err := s.DeferSide(ctx, *j, "side_driver_unavailable", r.Evidence); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(r.Evidence)
	pendingCount(t, s.db, 1, "SELECT count(*) FROM side_jobs WHERE state='inconclusive' AND evidence=?", string(encoded))
}

func TestSideV57ExhaustedRevokedTokenSettles(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	id, _ := newExportSource(t, s, "revoked-last-attempt", sourceURI(52))
	j := sideClaim(t, s)
	if _, err := s.db.Exec("UPDATE side_jobs SET attempts=?", sideAttempts); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE sources SET enabled=0 WHERE id=?; UPDATE sources SET enabled=1 WHERE id=?", id); err != nil {
		t.Fatal(err)
	}
	if err := s.Expire(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, 1, "SELECT count(*) FROM side_jobs WHERE identity=? AND state='inconclusive' AND code='worker_lease_exhausted'", j.Identity)
}

func TestSideOriginalOnlyCompleteFailureIsRecordedAsRaw(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	newExportSource(t, s, "raw-first", sourceURI(400))
	j := sideClaim(t, s)
	r := sideReject(t, j)
	delete(r.Evidence, "candidate_sha256")
	r.Evidence["raw_checks"] = "failed"
	r.Evidence["measured_form"] = "raw"
	r.Evidence["raw_input_sha256"] = repair.Digest(nil)
	if validSideEvidence(r) {
		t.Fatal("failed original from another source")
	}
	r.Evidence["raw_input_sha256"] = j.Hash
	r.Evidence["warp"] = "passed"
	if validSideEvidence(r) {
		t.Fatal("a raw-only pass cannot reject or qualify")
	}
	r.Evidence["warp"] = "warp_not_active"
	if err := s.CompleteSide(ctx, r); err != nil {
		t.Fatal(err)
	}
	form, checks := sideReviewChecks(r.Evidence)
	if form != "raw" || checks["warp"] != "warp_not_active" {
		t.Fatal(form, checks)
	}
	rate, err := readSideThroughput(ctx, s.reader())
	if err != nil || rate.Decided != 1 || rate.Full != 1 {
		t.Fatal(rate, err)
	}
}
