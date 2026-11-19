package panel

import (
	"context"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
	"testing"
)

func TestEgressCohortPreservesReceiptsAndLeases(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	newExportSource(t, s, "cohort", sourceURI(250), sourceURI(251), sourceURI(252))
	accepted, err := s.ClaimEgress(ctx)
	if err != nil || accepted == nil {
		t.Fatal(err)
	}
	if err = s.CompleteEgress(ctx, egress.Completion{Job: *accepted, Report: syntheticEgress(*accepted)}); err != nil {
		t.Fatal(err)
	}
	inFlight, err := s.ClaimEgress(ctx)
	if err != nil || inFlight == nil {
		t.Fatal(err)
	}
	prior := egress.Completion{Job: *inFlight, Report: syntheticEgress(*inFlight)}
	prior.Report.Started--
	before, err := egressMetricState(ctx, s.db)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.ResetEgress(ctx, 0)
	if err != nil || id != 1 {
		t.Fatal(id, err)
	}
	if _, err = s.ResetEgress(ctx, 0); err != ErrConflict {
		t.Fatal("stale revision", err)
	}
	if same, err := s.ResetEgress(ctx, id); err != nil || same != id {
		t.Fatal("active cohort duplicated", same, err)
	}
	var eligible int
	if err = s.db.QueryRow("SELECT count(*) FROM egress_export_eligible WHERE hash=?", accepted.Hash).Scan(&eligible); err != nil || eligible != 1 {
		t.Fatal("accepted proof invalidated", eligible, err)
	}
	if err = s.CompleteEgress(ctx, prior); err != nil {
		t.Fatal("active lease interrupted", err)
	}
	if err = s.CompleteEgress(ctx, prior); err != ErrConflict {
		t.Fatal("duplicate completion", err)
	}
	run, err := egressRunState(ctx, s.db)
	if err != nil || run["total"] != 2 || run["completed"] != 1 || run["pending"] != 1 || run["accepted"] != 0 {
		t.Fatal(run, err)
	}
	fresh, err := s.ClaimEgressLane(ctx, "initial")
	if err != nil || fresh == nil || fresh.Hash == accepted.Hash || fresh.Hash == inFlight.Hash || fresh.Attempt != 1 {
		t.Fatal("expected untouched identity", fresh, err)
	}
	if err = s.CompleteEgress(ctx, egress.Completion{Job: *fresh, Report: syntheticEgress(*fresh)}); err != nil {
		t.Fatal(err)
	}
	after, err := egressMetricState(ctx, s.db)
	if err != nil || after.Completed != before.Completed+2 || after.FirstAssessments != before.FirstAssessments+2 {
		t.Fatal("lifetime accounting", before, after, err)
	}
	if same, err := s.ResetEgress(ctx, id); err != nil || same != id {
		t.Fatal("empty cohort duplicated", same, err)
	}
	newExportSource(t, s, "next", sourceURI(262))
	nextID, err := s.ResetEgress(ctx, id)
	if err != nil || nextID != id+1 {
		t.Fatal(nextID, err)
	}
	var priorCount int
	if err = s.db.QueryRow("SELECT count(*) FROM egress_run_members WHERE run=? AND status='completed'", id).Scan(&priorCount); err != nil || priorCount != 2 {
		t.Fatal("previous cohort audit lost", priorCount, err)
	}
}

func TestEgressResetPreservesBlockedPausedAndManualExclusions(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	newExportSource(t, s, "guards", sourceURI(253), sourceURI(254), sourceURI(255), sourceURI(256))
	rows, err := s.db.Query("SELECT hash,identity FROM egress_owners ORDER BY hash")
	if err != nil {
		t.Fatal(err)
	}
	type item struct{ hash, identity string }
	all := []item{}
	for rows.Next() {
		var i item
		if err = rows.Scan(&i.hash, &i.identity); err != nil {
			t.Fatal(err)
		}
		all = append(all, i)
	}
	rows.Close()
	if len(all) != 4 {
		t.Fatal(len(all))
	}
	if _, err = s.db.Exec("INSERT INTO egress_iran_guard(identity,state,first_seen) VALUES(?,'BLOCKED',1)", all[0].identity); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("INSERT INTO input_exclusions(identity,at,hash,manual) VALUES(?,1,?,1)", all[1].identity, all[1].hash); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("UPDATE egress_jobs SET paused=1 WHERE hash=?", all[2].hash); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ResetEgress(ctx, 0); err != nil {
		t.Fatal(err)
	}
	run, err := egressRunState(ctx, s.db)
	if err != nil || run["total"] != 1 {
		t.Fatal(run, err)
	}
	var guards, exclusions, paused int
	s.db.QueryRow("SELECT count(*) FROM egress_iran_guard WHERE state='BLOCKED'").Scan(&guards)
	s.db.QueryRow("SELECT count(*) FROM input_exclusions").Scan(&exclusions)
	s.db.QueryRow("SELECT count(*) FROM egress_jobs WHERE paused=1").Scan(&paused)
	if guards != 1 || exclusions != 1 || paused != 1 {
		t.Fatal(guards, exclusions, paused)
	}
	tx, _ := s.db.Begin()
	if err = s.revokeEgress(ctx, tx, all[3].hash, "manual_delete", egress.Now()); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	run, err = egressRunState(ctx, s.db)
	if err != nil || run["excluded"] != 1 || run["completed"] != 0 || run["finished"] != true {
		t.Fatal(run, err)
	}
}

func TestEgressRunCountsConfirmedIranCompletionAsTested(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	newExportSource(t, s, "iran-round", sourceURI(257))
	if _, err := s.ResetEgress(ctx, 0); err != nil {
		t.Fatal(err)
	}
	j, err := s.ClaimEgress(ctx)
	if err != nil || j == nil {
		t.Fatal(err)
	}
	// Revocation marks the other members excluded, while the actual measured
	// member must be completed, even when the deletion trigger ran first.
	tx, _ := s.db.Begin()
	if err = s.revokeEgress(ctx, tx, j.Hash, "confirmed_ads_iran", egress.Now()); err != nil {
		t.Fatal(err)
	}
	if err = recordEgressRun(ctx, tx, j.Hash, "DELETED", false, egress.Now(), 20); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	run, err := egressRunState(ctx, s.db)
	if err != nil || run["completed"] != 1 || run["excluded"] != 0 || run["definitive"] != 0 {
		t.Fatal(run, err)
	}
}

func TestEgressManualDeleteFencesAllAliasesWithoutInventingHealthDeletion(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	newExportSource(t, s, "alias-delete", sourceURI(258), sourceURI(259))
	first, _ := s.ClaimEgress(ctx)
	second, _ := s.ClaimEgress(ctx)
	var identity string
	if err := s.db.QueryRow("SELECT identity FROM egress_owners WHERE hash=? LIMIT 1", first.Hash).Scan(&identity); err != nil {
		t.Fatal(err)
	}
	// Bind an existing in-flight alternate representation to the same identity.
	if _, err := s.db.Exec("UPDATE egress_owners SET identity=? WHERE hash=?", identity, second.Hash); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResetEgress(ctx, 0); err != nil {
		t.Fatal(err)
	}
	stale := second
	tx, _ := s.db.Begin()
	if err := s.revokeEgress(ctx, tx, first.Hash, "manual_delete", egress.Now()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var live int
	s.db.QueryRow("SELECT count(*) FROM egress_jobs WHERE state!='DELETED'").Scan(&live)
	if live != 0 {
		t.Fatal("alias remained in active queue", live)
	}
	if err := s.CompleteEgress(ctx, egress.Completion{Job: *stale, Report: syntheticEgress(*stale)}); err != ErrConflict {
		t.Fatal("alias lease survived exclusion", err)
	}
	run, err := egressRunState(ctx, s.db)
	if err != nil || run["excluded"] != 2 || run["pending"] != 0 {
		t.Fatal(run, err)
	}
	metrics, _ := egressMetricState(ctx, s.db)
	if metrics.UnhealthyDeleted != 0 {
		t.Fatal("manual deletion counted as health failure")
	}
}
