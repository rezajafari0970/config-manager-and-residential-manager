package panel

import (
	"context"
	"encoding/json"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
	"net/http/httptest"
	"testing"
)

func TestEgressAccountingPartitionsAndOutputUnits(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	newExportSource(t, s, "accounting", sourceURI(251), sourceURI(252), sourceURI(253), sourceURI(254), sourceURI(255), sourceURI(256))
	hashes := []string{}
	jobs := map[string]egress.Job{}
	for range 6 {
		j, err := s.ClaimEgress(ctx)
		if err != nil || j == nil {
			t.Fatal(err)
		}
		hashes = append(hashes, j.Hash)
		jobs[j.Hash] = *j
	}
	now := egress.Now()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := s.db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	// Two raw versions can legitimately emit the same template. Keep both rows.
	for _, h := range hashes[:2] {
		j := jobs[h]
		if err := s.CompleteEgress(ctx, egress.Completion{Job: j, Report: syntheticEgress(j)}); err != nil {
			t.Fatal(err)
		}
	}
	exec("UPDATE egress_jobs SET candidate_hash=(SELECT candidate_hash FROM egress_jobs WHERE hash=?) WHERE hash=?", hashes[0], hashes[1])
	exec("UPDATE egress_network_results SET candidate_hash=(SELECT candidate_hash FROM egress_jobs WHERE hash=?) WHERE hash=?", hashes[1], hashes[1])
	exec("UPDATE egress_jobs SET paused=1 WHERE hash=?", hashes[2])
	exec("UPDATE egress_jobs SET token='',lease_until=0,next_run=0 WHERE hash=?", hashes[3])
	exec("UPDATE egress_jobs SET token='',lease_until=0,next_run=?,tested=1 WHERE hash=?", now+60000, hashes[4])
	exec("DELETE FROM memberships WHERE raw_hash=?", hashes[4])
	// Sixth is actively leased: never count it again as due.
	frozen := context.WithValue(ctx, readTimeKey{}, now)
	q, err := freezeEgress(frozen, s.db)
	if err != nil {
		t.Fatal(err)
	}
	a, err := egressAccounting(frozen, q)
	if err != nil {
		t.Fatal(err)
	}
	queue := a["queue"].(map[string]int)
	pub := a["publication"].(map[string]int)
	if a["live_versions"] != 5 || a["current_versions"] != 5 || a["archive_versions"] != 0 || a["awaiting_first"] != 3 || a["assessed_versions"] != 2 {
		t.Fatal(a)
	}
	if queue["paused"] != 1 || queue["running"] != 1 || queue["due"] != 1 || queue["scheduled"] != 2 {
		t.Fatal(queue)
	}
	if pub["published"] != 2 || pub["distinct_templates"] != 1 || pub["identities"] != 2 || pub["awaiting_proof"] != 0 {
		t.Fatal(pub)
	}
	// Expiry is computed at the same frozen clock, even before maintenance runs.
	exec("UPDATE egress_jobs SET valid_until=? WHERE hash=?", now-1, hashes[0])
	a, err = egressAccounting(frozen, q)
	if err != nil {
		t.Fatal(err)
	}
	pub = a["publication"].(map[string]int)
	if pub["route_verified"] != 1 || pub["eligible"] != 1 || pub["awaiting_proof"] != 1 || pub["published"] != 1 {
		t.Fatal(pub)
	}
	renewal := a["renewal"].(map[string]int)
	sum := 0
	for _, n := range renewal {
		sum += n
	}
	if sum != pub["awaiting_proof"] {
		t.Fatal("renewal partition diverged", renewal, pub)
	}
	exec("UPDATE egress_country_policy SET allowed='[]'")
	a, err = egressAccounting(frozen, q)
	if err != nil {
		t.Fatal(err)
	}
	pub = a["publication"].(map[string]int)
	if pub["published"] != 0 || pub["country_filtered"] != 1 || pub["retained"] != 2 {
		t.Fatal(pub)
	}
	exec("UPDATE egress_settings SET enabled=0")
	a, err = egressAccounting(frozen, q)
	if err != nil {
		t.Fatal(err)
	}
	queue, renewal = a["queue"].(map[string]int), a["renewal"].(map[string]int)
	if queue["running"] != 1 || queue["paused"] != 4 || queue["due"] != 0 || queue["scheduled"] != 0 || renewal["paused"] != 2 || renewal["due"] != 0 || renewal["scheduled"] != 0 {
		t.Fatal("disabled dispatcher advertised work", queue, renewal)
	}

}

func TestEgressDueAcceptedUsesReservedEarlyRenewal(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	newExportSource(t, s, "lead", sourceURI(257), sourceURI(258))
	j, _ := s.ClaimEgress(ctx)
	if err := s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: syntheticEgress(*j)}); err != nil {
		t.Fatal(err)
	}
	// A slow probe is deliberately due four minutes before proof expiry. The
	// reserved follow-up lane starts it while initial capacity remains available.
	if _, err := s.db.Exec("UPDATE egress_jobs SET next_run=0,valid_until=? WHERE hash=?", egress.Now()+240000, j.Hash); err != nil {
		t.Fatal(err)
	}
	renewal, err := s.ClaimEgressLane(ctx, "followup")
	if err != nil || renewal == nil || renewal.Hash != j.Hash {
		t.Fatal("renewal lead ignored", renewal, err)
	}
	fresh, err := s.ClaimEgressLane(ctx, "initial")
	if err != nil || fresh == nil || fresh.Hash == j.Hash {
		t.Fatal("fresh work or lease isolation lost", fresh, err)
	}
}

func TestEgressThroughputCountsDistinctConclusiveInputs(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	newExportSource(t, s, "attempts", sourceURI(259))
	for range 3 {
		s.db.Exec("UPDATE egress_jobs SET next_run=0")
		j, _ := s.ClaimEgress(ctx)
		if err := s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: syntheticEgress(*j)}); err != nil {
			t.Fatal(err)
		}
	}
	app, _ := NewServer(s, "http://127.0.0.1:18191")
	rr := httptest.NewRecorder()
	egressModule{app}.state(rr, httptest.NewRequest("GET", "/api/egress?brief=1", nil))
	var v struct {
		Throughput map[string]int `json:"throughput"`
	}
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &v) != nil {
		t.Fatal(rr.Code, rr.Body.String())
	}
	if v.Throughput["completed_10m"] != 3 || v.Throughput["definitive_10m"] != 3 || v.Throughput["unique_definitive_10m"] != 1 {
		t.Fatal(v)
	}
}

func TestEgressExpiredHoldsStayOutOfResidentialRenewalCounts(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	newExportSource(t, s, "held-renewal-accounting", sourceURI(701), sourceURI(702), sourceURI(703), sourceURI(704))
	var hashes []string
	for i := 0; i < 4; i++ {
		job, err := s.ClaimEgress(ctx)
		if err != nil || job == nil {
			t.Fatal("expected fresh job", err)
		}
		report := syntheticEgress(*job)
		if i == 0 {
			for j := range report.Samples {
				x := &report.Samples[j]
				if x.ActualAds {
					x.Network.Kind, x.Network.Provider, x.Network.ASN = "hosting", "vultr", 20473
				}
			}
		}
		if err = s.CompleteEgress(ctx, egress.Completion{Job: *job, Report: report}); err != nil {
			t.Fatal(err)
		}
		hashes = append(hashes, job.Hash)
	}
	now := egress.Now()
	ctx = context.WithValue(ctx, readTimeKey{}, now)
	q, err := freezeEgress(ctx, s.db)
	if err != nil {
		t.Fatal(err)
	}
	check := func(verified, published, renewalDue, network, iran, loss, conflict int) {
		t.Helper()
		a, err := egressAccounting(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		p := a["publication"].(map[string]int)
		r := a["renewal"].(map[string]int)
		v := a["safety_review"].(map[string]int)
		if p["published"] != published || p["route_verified"] != verified || p["retained"] != verified+renewalDue+network+iran+loss+conflict ||
			p["awaiting_proof"] != renewalDue || r["due"] != renewalDue || r["running"]+r["scheduled"]+r["paused"]+r["cached"] != 0 ||
			v["network"] != network || v["iran"] != iran || v["route_or_health_loss"] != loss || v["country_conflict"] != conflict {
			t.Fatal(p, r, v)
		}
	}
	check(4, 3, 0, 0, 0, 0, 0)
	if _, err = s.db.Exec("UPDATE egress_jobs SET valid_until=1,next_run=0"); err != nil {
		t.Fatal(err)
	}
	check(0, 0, 3, 1, 0, 0, 0)
	if _, err = s.db.Exec("INSERT INTO egress_iran_guard(identity,state,first_seen) SELECT identity,'QUARANTINED',? FROM egress_unique WHERE hash=?", now, hashes[1]); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("INSERT INTO egress_retirements(hash,reason,hits,at,first_at) VALUES (?, 'confirmed_ads_route_lost', 1, ?, ?)", hashes[2], now, now); err != nil {
		t.Fatal(err)
	}
	check(0, 0, 1, 1, 1, 1, 0)
	// A minority-IR country conflict is a veto without a confirmed Iran hit.
	// A conflict that overlaps Iran quarantine must count only once.
	if _, err = s.db.Exec(`UPDATE egress_jobs SET decision=json_set(decision,'$.country_conflict',1) WHERE hash IN (?,?)`, hashes[1], hashes[3]); err != nil {
		t.Fatal(err)
	}
	check(0, 0, 0, 1, 1, 1, 1)
}
