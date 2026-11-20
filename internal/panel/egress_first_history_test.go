package panel

import (
	"context"
	"os"
	"path/filepath"
	"testing"
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
	if err := s.migrateV52(true); err != nil {
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
