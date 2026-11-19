package panel

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

// A completed datacenter result stays cached even after its proof expires.
func TestEgressHeldExpiryDoesNotDisplaceUntested(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	newExportSource(t, s, "held", sourceURI(890))
	held, err := s.ClaimEgress(ctx)
	if err != nil || held == nil {
		t.Fatal(err)
	}
	r := syntheticEgress(*held)
	for i := range r.Samples {
		sample := &r.Samples[i]
		if sample.ActualAds {
			sample.Network.Kind, sample.Network.Provider, sample.Network.ASN = "hosting", "vultr", 20473
		}
	}
	if err = s.CompleteEgress(ctx, egress.Completion{Job: *held, Report: r}); err != nil {
		t.Fatal(err)
	}
	newExportSource(t, s, "fresh", sourceURI(891))
	if _, err = s.db.Exec("UPDATE egress_jobs SET next_run=0,valid_until=? WHERE hash=?", egress.Now()+60000, held.Hash); err != nil {
		t.Fatal(err)
	}
	fresh, err := s.ClaimEgressLane(ctx, "initial")
	if err != nil || fresh == nil || fresh.Hash == held.Hash {
		t.Fatal("held expiry displaced fresh input", err)
	}
	ordinary, err := s.ClaimEgressLane(ctx, "followup")
	if err != nil || ordinary != nil {
		t.Fatal("held datacenter result re-entered the queue", ordinary, err)
	}
}

func TestEgressDispatchGuaranteesBothClassesDuringContention(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lanes []string
		first []bool
	}{
		{"only initial worker", []string{"initial"}, []bool{true, true, false, true, true, false}},
		{"only follow-up worker", []string{"followup"}, []bool{false, false, true, false, false, true}},
		{"independent lanes", []string{"initial", "followup"}, []bool{true, false, true, false, true, false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			var inputs []string
			for i := 0; i < 12; i++ {
				inputs = append(inputs, sourceURI(180+i))
			}
			newExportSource(t, s, "both-classes", inputs...)
			now := egress.Now()
			for index, raw := range inputs[6:] {
				hash := egress.Hash([]byte(raw))
				reason := "ads_profiles_verified"
				if index == 0 {
					reason = "ads_iran_quarantined"
				}
				if _, err := s.db.Exec("UPDATE egress_jobs SET ever_accepted=1,first_completed=1,tested=?,valid_until=?,reason=?,next_run=0 WHERE hash=?", now, now+60000, reason, hash); err != nil {
					t.Fatal(err)
				}
				if index == 1 {
					if _, err := s.db.Exec("INSERT INTO egress_retirements(hash,reason,hits,at) VALUES(?,'confirmed_ads_delivery_unhealthy',1,?)", hash, now-60000); err != nil {
						t.Fatal(err)
					}
				}
			}
			path, key := filepath.Join(filepath.Dir(s.vault.Directory()), "panel.db"), s.key
			maintenance := 0
			for i, wantFirst := range tc.first {
				// Each restart loses all worker and Store-local turn counters.
				if i == 2 || i == 4 {
					if err := s.Close(); err != nil {
						t.Fatal(err)
					}
					reopened, err := Open(path, key)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { reopened.Close() })
					s = reopened
				}
				job, err := s.ClaimEgressLane(ctx, tc.lanes[i%len(tc.lanes)])
				if err != nil || job == nil || (!job.Accepted) != wantFirst {
					t.Fatalf("grant %d: want discovery %v, got %v, err %v", i+1, wantFirst, job, err)
				}
				if !wantFirst {
					if maintenance < 2 && job.Hash != egress.Hash([]byte(inputs[6+maintenance])) {
						t.Fatal("maintenance lost Iran or retirement priority", maintenance, job.Hash)
					}
					maintenance++
				}
			}
		})
	}
}

func TestEgressConcurrentClaimantsShareCommittedDispatchStreak(t *testing.T) {
	s := testStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var inputs []string
	for i := 0; i < 12; i++ {
		inputs = append(inputs, sourceURI(200+i))
	}
	newExportSource(t, s, "concurrent-dispatch", inputs...)
	for _, raw := range inputs[6:] {
		if _, err := s.db.Exec("UPDATE egress_jobs SET ever_accepted=1,first_completed=1,tested=1 WHERE hash=?", egress.Hash([]byte(raw))); err != nil {
			t.Fatal(err)
		}
	}
	second, err := Open(filepath.Join(filepath.Dir(s.vault.Directory()), "panel.db"), s.key)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	type result struct {
		job *egress.Job
		err error
	}
	claims := make(chan result, 6)
	for i := range 6 {
		store := []*Store{s, second}[i%2]
		go func() {
			for {
				job, err := store.ClaimEgressLane(ctx, "followup")
				if err != nil || job != nil {
					claims <- result{job, err}
					return
				}
			}
		}()
	}
	seen := map[string]bool{}
	first := 0
	for range 6 {
		got := <-claims
		if got.err != nil || got.job == nil || seen[got.job.Hash] {
			t.Fatal("missing or duplicate concurrent claim", got.err)
		}
		seen[got.job.Hash] = true
		if !got.job.Accepted {
			first++
		}
	}
	if first != 2 {
		t.Fatal("six contending follow-up claims did not grant two initial leases", first)
	}
}

func TestEgressReadyFirstFIFOOverRefetchAndWithdrawal(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	oldRaw, newRaw := sourceURI(140), sourceURI(141)
	source, _ := newExportSource(t, s, "first-fifo", oldRaw)
	old := egress.Hash([]byte(oldRaw))
	newHash := egress.Hash([]byte(newRaw))
	// Rotate the old representative out without completing its first test.
	// The new candidate has next_run zero while the withdrawn one has a due
	// nonzero timestamp from a previous backoff.
	job := claimOne(t, s, source)
	if err := s.Complete(ctx, job, acquisitionResult(t, s, newRaw), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE egress_unique SET created=CASE hash WHEN ? THEN 100 ELSE 200 END", old); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE egress_jobs SET next_run=? WHERE hash=?", egress.Now()-1000, old); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_first_backlog WHERE hash=?", old)
	pendingCount(t, s.db, 0, "SELECT count(*) FROM memberships WHERE raw_hash=?", old)
	for _, want := range []string{old, newHash} {
		got, err := s.ClaimEgressLane(ctx, "initial")
		if err != nil || got == nil || got.Hash != want {
			t.Fatal("wrong ready discovery order", got, err)
		}
	}
}

func TestEgressVerifiedDeadlineBorrowsOnlyOneAdditionalMaintenanceGrant(t *testing.T) {
	for _, tc := range []struct {
		name string
		left int64
	}{
		{"approaching", 15000}, {"expired", -15000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			newExportSource(t, s, "maintenance-pressure", sourceURI(230), sourceURI(231), sourceURI(232), sourceURI(233))
			for range 4 {
				j, err := s.ClaimEgressLane(ctx, "initial")
				if err != nil || j == nil {
					t.Fatal("initial fixture grant", err)
				}
				if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: syntheticEgress(*j)}); err != nil {
					t.Fatal(err)
				}
			}
			newExportSource(t, s, "fresh-during-deadlines", sourceURI(235), sourceURI(236))
			if _, err := s.db.Exec("UPDATE egress_jobs SET valid_until=?,next_run=0 WHERE ever_accepted=1", egress.Now()+tc.left); err != nil {
				t.Fatal(err)
			}
			guard := egress.Hash([]byte(sourceURI(236)))
			for i := 0; i < 4; i++ {
				if i == 2 {
					// A newly arrived safety confirmation normally has the highest
					// maintenance priority. This exceptional slot belongs solely
					// to an individual proof whose deadline is threatened.
					if _, err := s.db.Exec("UPDATE egress_jobs SET first_completed=1,ever_accepted=1,tested=1,valid_until=0,reason='ads_iran_quarantined' WHERE hash=?", guard); err != nil {
						t.Fatal(err)
					}
				}
				j, err := s.ClaimEgressLane(ctx, "initial")
				if err != nil || j == nil || j.Accepted != (i < 3) || j.Hash == guard {
					t.Fatalf("deadline pressure grant %d: %+v, %v", i+1, j, err)
				}
			}
			// After the reserved discovery, the normal initial slot can again
			// help with urgent work. The safety confirmation must not starve
			// behind a continuous stream of expiring residential receipts.
			j, err := s.ClaimEgressLane(ctx, "initial")
			if err != nil || j == nil || j.Hash != guard {
				t.Fatal("urgent renewals starved a due safety confirmation", j, err)
			}
		})
	}
}
