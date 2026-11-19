package panel

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func TestV49ReplaysOriginalNetworkReceiptsWithNoNewProofLifetime(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := s.db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	var sharedHash string
	var validUntil int64
	for i, mode := range []string{"ordinary", "hosting", "split-with-shared", "later-clean", "unrelated-healthy"} {
		newExportSource(t, s, mode, sourceURI(930+i))
		j, err := s.ClaimEgress(ctx)
		if err != nil || j == nil {
			t.Fatal("initial", mode, err)
		}
		r := syntheticEgress(*j)
		if mode == "split-with-shared" {
			r = partialProfileReport(*j)
		}
		old := egress.NetworkVerdict{Version: egress.NetworkVersion, State: "hosting", Reason: "ads_hosting_exit", Provider: "vultr", ASN: 20473}
		for k := range r.Samples {
			x := &r.Samples[k]
			if !x.ActualAds {
				continue
			}
			if mode == "ordinary" {
				x.Source = egress.Hash([]byte("1.1.1.1"))
			}
			if mode == "hosting" || mode == "ordinary" || mode == "split-with-shared" && x.Source == egress.Hash([]byte("1.1.1.1")) {
				x.Network.Kind, x.Network.Provider, x.Network.ASN, x.Network.Source = "hosting", old.Provider, old.ASN, x.Source
				f := egress.NetworkFlow{Domain: x.Domain, Variant: x.Variant, Family: x.Family}
				if old.Domain == "" {
					old.Domain, old.Variant, old.Family = f.Domain, f.Variant, f.Family
				}
			}
		}
		if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: r}); err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(old)
		switch mode {
		case "unrelated-healthy":
			exec("UPDATE egress_jobs SET next_run=? WHERE hash=?", int64(9999999999999), j.Hash)
		case "later-clean":
			// The sticky rejection came from a different earlier measurement.
			exec("UPDATE egress_network_results SET held=1,last_adverse=?,policy=? WHERE hash=?", string(b), egress.NetworkVersion, j.Hash)
		default:
			exec("UPDATE egress_network_results SET held=1,state='hosting',summary=?,last_adverse=?,policy=? WHERE hash=?", string(b), string(b), egress.NetworkVersion, j.Hash)
		}
		if mode == "split-with-shared" {
			sharedHash = j.Hash
			if err = s.db.QueryRow("SELECT valid_until FROM egress_jobs WHERE hash=?", j.Hash).Scan(&validUntil); err != nil {
				t.Fatal(err)
			}
		}
	}
	exec("UPDATE metadata SET value=? WHERE key='ads-exit-network-policy'", egress.NetworkVersion)
	exec("DELETE FROM egress_residential_history")
	exec("PRAGMA user_version=48")
	if err := s.reconcileEgressNetworkPolicy(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.migrateV49(); err != nil {
			t.Fatal(err)
		}
	}
	pendingCount(t, s.db, 1, "SELECT count(*) "+datacenterRejectedFrom)
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_network_review WHERE attempts=0")
	pendingCount(t, s.db, 2, "SELECT count(*) FROM egress_export_eligible")
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_export_eligible WHERE hash=? AND valid_until=?", sharedHash, validUntil)
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_jobs WHERE state='NO_SPLIT' AND hash NOT IN(SELECT hash FROM egress_work)")
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_jobs WHERE next_run=9999999999999")
	accounting, err := egressAccounting(ctx, s.db)
	if err != nil {
		t.Fatal(err)
	}
	p := accounting["publication"].(map[string]int)
	if p["network_unverified"] != 1 || p["eligible_network_unattributed"] < 0 {
		t.Fatal(p)
	}
}

func TestV49ArchivedReviewBoundedAcrossExpiredLeasesAndSourceRefresh(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	raw := sourceURI(940)
	newExportSource(t, s, "archive", raw)
	j, err := s.ClaimEgress(ctx)
	if err != nil || j == nil {
		t.Fatal(err)
	}
	if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: syntheticEgress(*j)}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`UPDATE egress_network_results SET held=1, checked_at=1,policy='ads-exit-network.v1';
	DELETE FROM egress_residential_history; DELETE FROM memberships; UPDATE egress_jobs SET ever_accepted=0,next_run=9999999999999;
	PRAGMA user_version=48`); err != nil {
		t.Fatal(err)
	}
	if err = s.migrateV49(); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_work")
	pendingCount(t, s.db, 0, "SELECT count(*) "+datacenterRejectedFrom)
	pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_export_eligible")
	for i := 1; i <= 2; i++ {
		job, e := s.ClaimEgress(ctx)
		if e != nil || job == nil || job.Hash != j.Hash {
			t.Fatal("lost archived review", i, e)
		}
		pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_network_review WHERE attempts=?", i)
		if _, e = s.db.Exec("UPDATE egress_jobs SET lease_until=1 WHERE hash=?", job.Hash); e != nil {
			t.Fatal(e)
		}
		if e = s.CompleteEgress(ctx, egress.Completion{Job: *job, Report: syntheticEgress(*job)}); e != ErrConflict {
			t.Fatal("late review receipt", e)
		}
	}
	if err = s.Expire(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	newExportSource(t, s, "alias", raw+"-cosmetic")
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_inventory WHERE token=''")
	pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_work")
	if job, e := s.ClaimEgress(ctx); e != nil || job != nil {
		t.Fatal("rearmed exhausted review", e)
	}
	pendingCount(t, s.db, 0, "SELECT count(*) "+datacenterRejectedFrom)
	pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_export_eligible")
}

func TestVerifiedResidentialMaintenanceResumesAfterExpeditedNetworkReview(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	newExportSource(t, s, "retained", sourceURI(941))
	complete := func(kind string) {
		t.Helper()
		if _, err := s.db.Exec("UPDATE egress_jobs SET next_run=0"); err != nil {
			t.Fatal(err)
		}
		j, err := s.ClaimEgress(ctx)
		if err != nil || j == nil {
			t.Fatal("missing assessment", kind, err)
		}
		r := syntheticEgress(*j)
		if kind == "isolated" {
			for i := range r.Samples {
				x := &r.Samples[i]
				if !x.ActualAds {
					continue
				}
				if x.Wave == 1 {
					x.Network.Kind, x.Network.Provider, x.Network.ASN = "hosting", "vultr", 20473
				} else {
					x.Network = nil
				}
			}
		}
		if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: r}); err != nil {
			t.Fatal(err)
		}
	}
	complete("healthy")
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_residential_history")
	for _, attempt := range []int{1, 2} {
		complete("isolated")
		pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_network_review WHERE attempts=?", attempt)
		pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_export_eligible")
		pendingCount(t, s.db, 0, "SELECT count(*) "+datacenterRejectedFrom)
	}
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_work WHERE next_run>?", egress.Now())
	complete("healthy")
	pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_network_review")
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_export_eligible")
}
