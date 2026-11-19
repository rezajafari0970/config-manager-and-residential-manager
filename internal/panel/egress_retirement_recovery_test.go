package panel

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func TestRetirementConfirmationSurvivesWithdrawalRestartAndExpiredEvidence(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	source, _ := newExportSource(t, s, "rotation", sourceURI(201))
	first, err := s.ClaimEgress(ctx)
	if err != nil || first == nil {
		t.Fatal("first claim", err)
	}
	commitProbeInputs(t, s, source, sourceURI(202))
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_first_backlog WHERE hash=?", first.Hash)
	if err = s.CompleteEgress(ctx, egress.Completion{Job: *first, Report: badDelivery(*first)}); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_first_backlog WHERE hash=?", first.Hash)
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_retirement_sources WHERE hash=? AND source_id=?", first.Hash, source)
	pendingCount(t, s.db, 1, "SELECT count(*) FROM input_blocked WHERE hash=?", first.Hash)
	if _, err = s.db.Exec("UPDATE egress_retirements SET first_at=1,at=1 WHERE hash=?", first.Hash); err != nil {
		t.Fatal(err)
	}
	path, key := filepath.Join(filepath.Dir(s.vault.Directory()), "panel.db"), s.key
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	present, err := freezeEgress(ctx, reopened.read(ctx))
	if err != nil {
		t.Fatal(err)
	}
	pendingCount(t, present, 1, "SELECT count(*) FROM egress_work WHERE hash=?", first.Hash)
	pendingCount(t, present, 0, "SELECT count(*) FROM egress_export_eligible WHERE hash=?", first.Hash)
	if ref, err := reopened.Referenced(ctx, first.Hash); err != nil || !ref {
		t.Fatal("raw confirmation input lost", ref, err)
	}
	for n := 1; n <= 3; n++ {
		if _, err := reopened.db.Exec("UPDATE egress_jobs SET next_run=CASE WHEN hash=? THEN 0 ELSE ? END", first.Hash, egress.Now()+3600000); err != nil {
			t.Fatal(err)
		}
		j, err := reopened.ClaimEgressLane(ctx, "followup")
		if err != nil || j == nil || j.Hash != first.Hash || j.Issue != "" {
			t.Fatal("missing sourced follow-up", n, err)
		}
		if err = reopened.RenewEgress(ctx, *j); err != nil {
			t.Fatal("last authorized grant cannot finish", err)
		}
		if n > 1 {
			if _, err = reopened.db.Exec("UPDATE egress_retirements SET at=? WHERE hash=?", egress.Now()-31000, first.Hash); err != nil {
				t.Fatal(err)
			}
		}
		if err = reopened.CompleteEgress(ctx, egress.Completion{Job: *j, Report: badDelivery(*j)}); err != nil {
			t.Fatal(err)
		}
		if n < 3 {
			pendingCount(t, reopened.db, n, "SELECT hits FROM egress_retirements WHERE hash=?", first.Hash)
			pendingCount(t, reopened.db, 0, "SELECT count(*) FROM input_exclusions")
		}
	}
	pendingCount(t, reopened.db, 1, "SELECT count(*) FROM input_exclusions")
	pendingCount(t, reopened.db, 0, "SELECT count(*) FROM egress_retirement_sources WHERE hash=?", first.Hash)
	pendingCount(t, reopened.db, 3, "SELECT count(*) FROM egress_events WHERE hash=? AND first_result_scope=''", first.Hash)
}

func TestRetirementConfirmationsCannotRefillAfterCrashOrUnknown(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	raw := sourceURI(203)
	id, _ := newExportSource(t, s, "one", raw)
	j, err := s.ClaimEgress(ctx)
	if err != nil || j == nil {
		t.Fatal(err)
	}
	hash := j.Hash
	if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: badDelivery(*j)}); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 3; n++ {
		if _, err = s.db.Exec("UPDATE egress_jobs SET next_run=0 WHERE hash=?", hash); err != nil {
			t.Fatal(err)
		}
		j, err = s.ClaimEgress(ctx)
		if err != nil || j == nil || j.Hash != hash {
			t.Fatal("missing grant", n, err)
		}
		if n == 0 {
			if _, err = s.db.Exec("UPDATE egress_jobs SET lease_until=1 WHERE hash=?", hash); err != nil {
				t.Fatal(err)
			}
			continue
		}
		now := egress.Now()
		r := egress.Report{Version: egress.Version, Hash: hash, Started: now, Finished: now, Code: "driver_session_failed"}
		if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: r}); err != nil {
			t.Fatal(err)
		}
	}
	fillExportSource(t, s, id, raw)
	newExportSource(t, s, "alias", raw+"-new")
	pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_work WHERE hash=?", hash)
	pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_retirement_sources WHERE hash=?", hash)
	pendingCount(t, s.db, 1, "SELECT count(*) FROM input_blocked WHERE hash=?", hash)
	pendingCount(t, s.db, 0, "SELECT count(*) FROM input_exclusions")
	pendingCount(t, s.db, 1, "SELECT hits FROM egress_retirements WHERE hash=?", hash)
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_events WHERE hash=? AND first_result_scope!=''", hash)
}

func TestRetirementOwnersFenceLeaseAcrossReplaceAndReenable(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	raw := sourceURI(204)
	one, _ := newExportSource(t, s, "one", raw)
	two, _ := newExportSource(t, s, "two", raw)
	j, err := s.ClaimEgress(ctx)
	if err != nil || j == nil {
		t.Fatal(err)
	}
	if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: badDelivery(*j)}); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, 2, "SELECT count(*) FROM egress_retirement_sources WHERE hash=?", j.Hash)
	if _, err = s.db.Exec("UPDATE egress_jobs SET next_run=0 WHERE hash=?", j.Hash); err != nil {
		t.Fatal(err)
	}
	j, err = s.ClaimEgress(ctx)
	if err != nil || j == nil {
		t.Fatal(err)
	}
	src, err := s.Get(ctx, one)
	if err != nil {
		t.Fatal(err)
	}
	src.URL += "/replaced"
	if _, err = s.Save(ctx, one, src.Revision, src.SourceInput); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_retirement_sources WHERE hash=?", j.Hash)
	if err = s.RenewEgress(ctx, *j); err != nil {
		t.Fatal("remaining owner lost lease", err)
	}
	for _, enabled := range []bool{false, true} {
		src, err = s.Get(ctx, two)
		if err != nil {
			t.Fatal(err)
		}
		src.Enabled = enabled
		if _, err = s.Save(ctx, two, src.Revision, src.SourceInput); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.RenewEgress(ctx, *j); err != ErrConflict {
		t.Fatal("old grant revived", err)
	}
	if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: syntheticEgress(*j)}); err != ErrConflict {
		t.Fatal("old success republished", err)
	}
	recovery, err := s.ClaimEgressLane(ctx, "followup")
	if err != nil || recovery == nil || recovery.Hash != j.Hash || recovery.Token == j.Token {
		t.Fatal("valid assignment after reenable", err)
	}
	if err = s.CompleteEgress(ctx, egress.Completion{Job: *recovery, Report: syntheticEgress(*recovery)}); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_export_eligible WHERE hash=?", j.Hash)
	pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_retirement_sources WHERE hash=?", j.Hash)
}

func TestRetirementMigrationUsesOnlyActiveOrProvenWithdrawnOwners(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	// These sources have not yet consumed their independent ordinary first
	// probes, so a natural rotation records exact received-byte provenance.
	add := func(name string, fixture int) string {
		t.Helper()
		input := testSource()
		input.URL += name
		id, err := s.Save(ctx, "", 0, input)
		if err != nil {
			t.Fatal(err)
		}
		commitProbeInputs(t, s, id, sourceURI(fixture))
		return id
	}
	one, two, three := add("current", 205), add("withdrawn", 206), add("unowned", 207)
	hashes := map[string]string{}
	for _, source := range []string{one, two, three} {
		var hash string
		if err := s.db.QueryRow("SELECT u.hash FROM memberships m JOIN egress_unique u ON u.identity=m.artifact_id WHERE m.source_id=?", source).Scan(&hash); err != nil {
			t.Fatal(err)
		}
		hashes[source] = hash
	}
	var inFlight []*egress.Job
	for range 3 {
		j, err := s.ClaimEgress(ctx)
		if err != nil || j == nil {
			t.Fatal(err)
		}
		inFlight = append(inFlight, j)
	}
	commitProbeInputs(t, s, two, sourceURI(208))
	commitProbeInputs(t, s, three, sourceURI(209))
	for _, j := range inFlight {
		if err := s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: badDelivery(*j)}); err != nil {
			t.Fatal(err)
		}
	}
	// Build the pre-v54 state. A former source sighting alone is not a
	// committed, authorized withdrawal for this representative.
	if _, err := s.db.Exec("DELETE FROM egress_retirement_limits; DELETE FROM conversion_first_backlog WHERE source_id=?; PRAGMA user_version=53", three); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_owners WHERE hash=? AND source=?", hashes[three], three)
	if err := s.migrateV54(); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{one, two, three} {
		want := 1
		if source == three {
			want = 0
		}
		pendingCount(t, s.db, want, "SELECT count(*) FROM egress_retirement_work WHERE hash=?", hashes[source])
		pendingCount(t, s.db, want, "SELECT count(*) FROM egress_retirement_sources WHERE source_id=? AND hash=?", source, hashes[source])
		pendingCount(t, s.db, 1, "SELECT hits FROM egress_retirements WHERE hash=?", hashes[source])
	}
	if _, err := s.db.Exec("DELETE FROM egress_retirement_sources WHERE source_id=?", two); err != nil {
		t.Fatal(err)
	}
	if err := s.migrateV54(); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_retirement_work WHERE hash=?", hashes[two])
}

func TestRetirementNewCommittedOwnerInheritsOnlyUnspentGrants(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	raw := sourceURI(210)
	oldID, _ := newExportSource(t, s, "previous", raw)
	j, err := s.ClaimEgress(ctx)
	if err != nil || j == nil {
		t.Fatal(err)
	}
	hash := j.Hash
	if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: badDelivery(*j)}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("UPDATE egress_jobs SET next_run=0 WHERE hash=?", hash); err != nil {
		t.Fatal(err)
	}
	spent, err := s.ClaimEgress(ctx)
	if err != nil || spent == nil || spent.Hash != hash {
		t.Fatal(err)
	}
	originalLimit := spent.Attempt + 2
	oldSource, err := s.Get(ctx, oldID)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Delete(ctx, oldID, oldSource.Revision); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_work WHERE hash=?", hash)
	pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_retirement_sources WHERE hash=?", hash)
	pendingCount(t, s.db, originalLimit, "SELECT through_attempt FROM egress_retirement_limits WHERE hash=?", hash)
	newID, _ := newExportSource(t, s, "successor", raw+"-alias")
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_retirement_sources WHERE hash=? AND source_id=?", hash, newID)
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_work WHERE hash=?", hash)
	pendingCount(t, s.db, originalLimit, "SELECT through_attempt FROM egress_retirement_limits WHERE hash=?", hash)
	if err = s.RenewEgress(ctx, *spent); err != ErrConflict {
		t.Fatal("deleted source token revived", err)
	}
	for n := 0; n < 2; n++ {
		if _, err = s.db.Exec("UPDATE egress_jobs SET next_run=0 WHERE hash=?", hash); err != nil {
			t.Fatal(err)
		}
		claim, err := s.ClaimEgress(ctx)
		if err != nil || claim == nil || claim.Hash != hash {
			t.Fatal("remaining grant", n, err)
		}
		now := egress.Now()
		r := egress.Report{Version: egress.Version, Hash: hash, Started: now, Finished: now, Code: "driver_session_failed"}
		if err = s.CompleteEgress(ctx, egress.Completion{Job: *claim, Report: r}); err != nil {
			t.Fatal(err)
		}
	}
	pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_work WHERE hash=?", hash)
}

func TestRetirementFinalCountryBlockClearsSimultaneousDeliveryFailure(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	newExportSource(t, s, "dual-signal", sourceURI(211))
	j, err := s.ClaimEgress(ctx)
	if err != nil || j == nil {
		t.Fatal(err)
	}
	hash := j.Hash
	if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: iranFixture(*j)}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("UPDATE egress_iran_guard SET last_round=1; UPDATE egress_jobs SET next_run=0"); err != nil {
		t.Fatal(err)
	}
	j, err = s.ClaimEgress(ctx)
	if err != nil || j == nil || j.Hash != hash {
		t.Fatal(err)
	}
	r := badDelivery(*j)
	r.Samples[0].Geo = iranFixture(*j).Samples[0].Geo
	if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: r}); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_iran_guard WHERE state='BLOCKED'")
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_jobs WHERE hash=? AND state='DELETED'", hash)
	pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_retirements WHERE hash=?", hash)
	// An already-issued terminal block can have a redundant legacy marker.
	if _, err = s.db.Exec(`INSERT INTO egress_retirements(hash,reason,hits,at,first_at)
 VALUES(?,'confirmed_ads_delivery_unhealthy',1,1,1); PRAGMA user_version=53`, hash); err != nil {
		t.Fatal(err)
	}
	if err = s.migrateV54(); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_retirements WHERE hash=?", hash)
	pendingCount(t, s.db, 1, "SELECT count(*) FROM input_exclusions")
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_iran_guard WHERE state='BLOCKED'")
}
