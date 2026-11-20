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

func TestV56RetiresArchivedV49ReviewAcrossSourceRefresh(t *testing.T) {
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
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err = migrateFreshResidential(tx); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if archived, err := s.ClaimEgress(ctx); err != nil || archived != nil {
		t.Fatal("replayed archived review", err)
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

// A new veto for a formerly qualified route may recover with two real clean
// completions. A second adverse receipt or two spent leases leaves it in DC.
func TestResidentialHostingConfirmationHasFiniteCustody(t *testing.T) {
	for _, outcome := range []string{"cleared", "confirmed", "crashed", "expired"} {
		t.Run(outcome, func(t *testing.T) {
			ctx := context.Background()
			s := testStore(t)
			raw := sourceURI(942)
			newExportSource(t, s, "hosting-change", raw)
			hash := egress.Hash([]byte(raw))
			exec := func(q string, args ...any) {
				t.Helper()
				if _, err := s.db.Exec(q, args...); err != nil {
					t.Fatal(err)
				}
			}
			claim := func() *egress.Job {
				t.Helper()
				exec("UPDATE egress_jobs SET next_run=0 WHERE hash=?", hash)
				j, err := s.ClaimEgressLane(ctx, "followup")
				if err != nil || j == nil || j.Hash != hash {
					t.Fatal("missing scheduled grant", err)
				}
				return j
			}
			measure := func(hosting bool) {
				t.Helper()
				j := claim()
				report := syntheticEgress(*j)
				if hosting {
					for i := range report.Samples {
						sample := &report.Samples[i]
						if sample.ActualAds {
							sample.Network.Kind, sample.Network.Provider, sample.Network.ASN = "hosting", "vultr", 20473
						}
					}
				}
				if err := s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: report}); err != nil {
					t.Fatal(err)
				}
			}
			measure(false)
			pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_export_eligible")
			measure(true)
			pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_export_eligible")
			pendingCount(t, s.db, 1, "SELECT count(*) "+datacenterRejectedFrom)
			pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_hosting_confirmations WHERE through_attempt=4")
			exec("UPDATE egress_jobs SET valid_until=?,next_run=?", egress.Now()+20000, egress.Now()+60000)
			if j, err := s.ClaimEgressLane(ctx, "initial"); err != nil || j != nil {
				t.Fatal("unpublished hold borrowed an early grant", err)
			}
			switch outcome {
			case "cleared":
				measure(false)
				pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_network_results WHERE held=1 AND clean_rounds=1")
				pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_export_eligible")
				measure(false)
				pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_export_eligible")
				pendingCount(t, s.db, 0, "SELECT count(*) "+datacenterRejectedFrom)
				return
			case "confirmed":
				measure(true)
			case "crashed":
				for range 2 {
					claim()
					exec("UPDATE egress_jobs SET lease_until=1 WHERE hash=?", hash)
				}
			case "expired":
				exec("UPDATE egress_hosting_confirmations SET expires=1")
			}
			newExportSource(t, s, "another-source", raw+"-cosmetic")
			exec("UPDATE egress_jobs SET next_run=0")
			if j, err := s.ClaimEgress(ctx); err != nil || j != nil {
				t.Fatal("exhausted hold restarted on refetch", err)
			}
			pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_export_eligible")
			pendingCount(t, s.db, 1, "SELECT count(*) "+datacenterRejectedFrom)
		})
	}
}
