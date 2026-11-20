package panel

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func TestNeverAcceptedDeliveryFailureDoesNotReenterDetection(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	raw := sourceURI(202)
	id, _ := newExportSource(t, s, "first", raw)
	newExportSource(t, s, "alias", raw+"-different-name")
	j, err := s.ClaimEgress(ctx)
	if err != nil || j == nil {
		t.Fatal(err)
	}
	if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: badDelivery(*j)}); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, 0, "SELECT count(*) FROM input_blocked WHERE hash=?", j.Hash)
	pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_retirement_sources WHERE hash=?", j.Hash)
	pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_work WHERE hash=?", j.Hash)
	commitProbeInputs(t, s, id, raw)
	key, path := s.key, filepath.Join(filepath.Dir(s.vault.Directory()), "panel.db")
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.db.Exec("UPDATE egress_jobs SET next_run=0 WHERE hash=?", j.Hash); err != nil {
		t.Fatal(err)
	}
	if retry, err := s.ClaimEgressLane(ctx, "followup"); err != nil || retry != nil {
		t.Fatal("the same rejected input got a second receipt", err)
	}
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_events WHERE hash=? AND first_result_scope!=''", j.Hash)
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
	for _, h := range hashes {
		if _, err := s.db.Exec(`INSERT INTO egress_retirements(hash,reason,hits,at,first_at) VALUES(?,'confirmed_ads_delivery_unhealthy',1,1,1)`, h); err != nil {
			t.Fatal(err)
		}
	}
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
