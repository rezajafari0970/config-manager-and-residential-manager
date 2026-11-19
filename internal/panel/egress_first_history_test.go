package panel

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

type historyFixture struct {
	source, identity, hash, raw string
}

// V46 had no first-work owner on natural withdrawal. Insert the input through
// normal collection, then reproduce that older removal (without the v47 ledger).
func historyInput(t *testing.T, s *Store, name string, number int) historyFixture {
	t.Helper()
	src := testSource()
	src.URL = "https://example.org/history/" + name
	id, err := s.Save(context.Background(), "", 0, src)
	if err != nil {
		t.Fatal(err)
	}
	raw := sourceURI(number)
	commitProbeInputs(t, s, id, raw)
	v := historyFixture{source: id, raw: raw}
	if err = s.db.QueryRow("SELECT artifact_id,raw_hash FROM memberships WHERE source_id=?", id).Scan(&v.identity, &v.hash); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("DELETE FROM memberships WHERE source_id=?", id); err != nil {
		t.Fatal(err)
	}
	return v
}

func exerciseHistoryUpgrade(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.db.Exec("PRAGMA user_version=51"); err != nil {
		t.Fatal(err)
	}
	if err := s.migrateV52(); err != nil {
		t.Fatal(err)
	}
}

func TestV52FirstHistoryRequiresCommittedUnambiguousUnmeasuredInput(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := s.db.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	var admitted, rejected []historyFixture
	for i, mode := range []string{"pristine", "edited-before-registration", "edited-after-registration", "old-claim", "prior-receipt", "independent-health-receipt", "paused", "iran", "excluded", "alternative-owner", "recorded-withdrawal", "current", "missing-blob", "tampered-blob"} {
		f := historyInput(t, s, mode, 185+i)
		switch mode {
		case "pristine":
		case "edited-before-registration":
			exec("UPDATE sources SET revision=2,updated=(SELECT created/1000-2 FROM egress_unique WHERE hash=?) WHERE id=?", f.hash, f.source)
		case "edited-after-registration":
			exec("UPDATE sources SET revision=2,updated=(SELECT created/1000+1 FROM egress_unique WHERE hash=?) WHERE id=?", f.hash, f.source)
		case "independent-health-receipt":
			exec("INSERT INTO egress_health(hash,status,checked_at,valid_until,report) VALUES(?,'unknown',1,0,'{}')", f.hash)
		case "old-claim":
			exec("UPDATE egress_jobs SET attempts=1,claimed_at=1 WHERE hash=?", f.hash)
		case "prior-receipt":
			exec("UPDATE egress_jobs SET first_completed=1,tested=1,state='NO_SPLIT',reason='all_tested_ads_share_control' WHERE hash=?", f.hash)
		case "paused":
			exec("UPDATE egress_jobs SET paused=1 WHERE hash=?", f.hash)
		case "iran":
			exec("INSERT INTO egress_iran_guard(identity,state,first_seen) VALUES(?,'QUARANTINED',1)", f.identity)
		case "excluded":
			exec("INSERT INTO input_exclusions(identity,at,hash,manual) VALUES(?,1,?,1)", f.identity, f.hash)
		case "alternative-owner":
			src := testSource()
			src.URL += "/alias-owner"
			id, err := s.Save(ctx, "", 0, src)
			if err != nil {
				t.Fatal(err)
			}
			exec("INSERT INTO egress_owners(hash,identity,source) VALUES(?,?,?)", f.hash, f.identity, id)
			v, err := s.Get(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.Delete(ctx, id, v.Revision); err != nil {
				t.Fatal(err)
			}
		case "recorded-withdrawal":
			exec("INSERT INTO egress_first_backlog(source_id,hash) VALUES(?,?)", f.source, f.hash)
		case "current":
			commitProbeInputs(t, s, f.source, f.raw)
		case "tampered-blob":
			path := filepath.Join(s.vault.Directory(), f.hash+".blob")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			raw[len(raw)-1] ^= 1
			if err = os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
		case "missing-blob":
			if err := os.Remove(filepath.Join(s.vault.Directory(), f.hash+".blob")); err != nil {
				t.Fatal(err)
			}
		}
		if mode == "pristine" || mode == "edited-before-registration" {
			admitted = append(admitted, f)
		} else {
			rejected = append(rejected, f)
		}
	}
	exerciseHistoryUpgrade(t, s)
	for _, f := range admitted {
		pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_first_history WHERE hash=? AND source_id=? AND phase='waiting'", f.hash, f.source)
	}
	for _, f := range rejected {
		pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_first_history WHERE hash=? AND phase IN ('waiting','active')", f.hash)
	}
	pendingCount(t, s.db, 2, "SELECT count(*) FROM egress_first_history WHERE phase='unavailable' AND raw_available=0")
	pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_export_eligible")
}

func TestV52FirstHistorySettlesOnceAcrossRestart(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	f := historyInput(t, s, "resume", 203)
	exerciseHistoryUpgrade(t, s)
	if _, err := s.db.Exec("UPDATE egress_first_history SET phase='active',ready_at=0 WHERE hash=?", f.hash); err != nil {
		t.Fatal(err)
	}
	j, err := s.ClaimEgressLane(ctx, "initial")
	if err != nil || j == nil || j.Hash != f.hash || string(j.Raw) != f.raw {
		t.Fatal("missing original archived bytes", err)
	}
	if err = s.RenewEgress(ctx, *j); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(s.vault.Directory()), "panel.db")
	key := s.key
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	r := syntheticEgress(*j)
	for i := range r.Samples {
		x := &r.Samples[i]
		x.Source = egress.Hash([]byte("1.1.1.1"))
		if x.Network != nil {
			x.Network.Source = x.Source
		}
	}
	if err = reopened.CompleteEgress(ctx, egress.Completion{Job: *j, Report: r}); err != nil {
		t.Fatal(err)
	}
	if err = reopened.CompleteEgress(ctx, egress.Completion{Job: *j, Report: r}); err != ErrConflict {
		t.Fatal("duplicate delivery accepted", err)
	}
	pendingCount(t, reopened.db, 1, "SELECT count(*) FROM egress_first_history WHERE hash=? AND phase='completed'", f.hash)
	pendingCount(t, reopened.db, 1, "SELECT count(*) FROM egress_jobs WHERE hash=? AND attempts=1 AND first_completed=1", f.hash)
	pendingCount(t, reopened.db, 0, "SELECT count(*) FROM egress_work WHERE hash=?", f.hash)
	pendingCount(t, reopened.db, 0, "SELECT count(*) FROM memberships WHERE artifact_id=?", f.identity)
	if err = reopened.migrateV52(); err != nil {
		t.Fatal(err)
	}
	if job, e := reopened.ClaimEgress(ctx); e != nil || job != nil {
		t.Fatal("completed receipt rearmed", e)
	}
}

func TestV52FirstHistoryHonorsOwnerChanges(t *testing.T) {
	for _, mode := range []string{"source-url", "source-deletion", "config-deletion", "pause-resume", "source-disable", "new-membership", "modern-withdrawal"} {
		t.Run(mode, func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			f := historyInput(t, s, "owner-change", 204)
			exerciseHistoryUpgrade(t, s)
			if _, err := s.db.Exec("UPDATE egress_first_history SET phase='active',ready_at=0 WHERE hash=?", f.hash); err != nil {
				t.Fatal(err)
			}
			j, err := s.ClaimEgress(ctx)
			if err != nil || j == nil || j.Hash != f.hash {
				t.Fatal("missing active history lease", err)
			}
			src, err := s.Get(ctx, f.source)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "source-url":
				src.URL += "/replacement"
				_, err = s.Save(ctx, f.source, src.Revision, src.SourceInput)
			case "source-disable":
				src.Enabled = false
				_, err = s.Save(ctx, f.source, src.Revision, src.SourceInput)
			case "source-deletion":
				err = s.Delete(ctx, f.source, src.Revision)
			case "config-deletion":
				_, err = s.ManageConfigs(ctx, ConfigBatch{Action: "delete", IDs: []string{f.identity}})
			case "pause-resume":
				_, err = s.ManageConfigs(ctx, ConfigBatch{Action: "disable", IDs: []string{f.identity}})
			case "new-membership":
				commitProbeInputs(t, s, f.source, f.raw)
			case "modern-withdrawal":
				_, err = s.db.Exec("INSERT INTO egress_first_backlog(source_id,hash) VALUES(?,?)", f.source, f.hash)
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "new-membership" || mode == "modern-withdrawal" {
				pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_first_history WHERE hash=? AND phase='promoted'", f.hash)
				if err = s.RenewEgress(ctx, *j); err != nil {
					t.Fatal("promoted owner lost valid lease", err)
				}
				return
			}
			if err = s.RenewEgress(ctx, *j); err != ErrConflict {
				t.Fatal("revoked claim renewed", err)
			}
			if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: syntheticEgress(*j)}); err != ErrConflict {
				t.Fatal("revoked claim completed", err)
			}
			if mode == "source-disable" {
				src, err = s.Get(ctx, f.source)
				if err != nil {
					t.Fatal(err)
				}
				src.Enabled = true
				if _, err = s.Save(ctx, f.source, src.Revision, src.SourceInput); err != nil {
					t.Fatal(err)
				}
				pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_first_history WHERE hash=? AND phase='waiting'", f.hash)
			} else if mode == "pause-resume" {
				if _, err = s.ManageConfigs(ctx, ConfigBatch{Action: "enable", IDs: []string{f.identity}}); err != nil {
					t.Fatal(err)
				}
				pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_first_history WHERE hash=? AND phase IN ('waiting','active')", f.hash)
			} else {
				pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_first_history WHERE hash=? AND phase IN ('waiting','active')", f.hash)
				pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_work WHERE hash=?", f.hash)
			}
			pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_export_eligible")
		})
	}
}

func TestV52FirstHistoryLosingPromotedOwner(t *testing.T) {
	for _, replaceOriginal := range []bool{false, true} {
		mode := "original-owner"
		if replaceOriginal {
			mode = "replaced-original"
		}
		t.Run(mode, func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			f := historyInput(t, s, "original", 205)
			exerciseHistoryUpgrade(t, s)
			src := testSource()
			src.URL = "https://example.org/history/additional"
			id, err := s.Save(ctx, "", 0, src)
			if err != nil {
				t.Fatal(err)
			}
			commitProbeInputs(t, s, id, f.raw)
			pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_first_history WHERE hash=? AND phase='promoted'", f.hash)
			if replaceOriginal {
				old, err := s.Get(ctx, f.source)
				if err != nil {
					t.Fatal(err)
				}
				old.URL += "/new"
				if _, err = s.Save(ctx, f.source, old.Revision, old.SourceInput); err != nil {
					t.Fatal(err)
				}
			}
			current, err := s.Get(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.Delete(ctx, id, current.Revision); err != nil {
				t.Fatal(err)
			}
			phase := "waiting"
			if replaceOriginal {
				phase = "cancelled"
			}
			pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_first_history WHERE hash=? AND phase=?", f.hash, phase)
			pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_export_eligible")
		})
	}
}
