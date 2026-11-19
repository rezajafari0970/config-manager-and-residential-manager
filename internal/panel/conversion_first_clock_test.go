package panel

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/probe"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
)

func TestOrdinaryClockCarriesInfrastructureBackoffAcrossRawAliases(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	raw := sourceURI(227)
	id, first := addConversion(t, s, raw)
	incomplete := func(j probe.Job) {
		t.Helper()
		r := conversionResult(j, 0, true)
		r.Core, r.Connection, r.Code = "blocked", "not_run", "probe_infrastructure_error"
		r.Candidate = nil
		if err := s.CompleteProbe(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	incomplete(first)
	var prior int64
	if err := s.db.QueryRow("SELECT retry_at FROM conversion_first_clock WHERE failures=1").Scan(&prior); err != nil || prior <= time.Now().UnixMilli() {
		t.Fatal("first failed attempt must defer the identity", prior, err)
	}
	alias := raw + "-new-label"
	commitProbeInputs(t, s, id, alias)
	hash := repair.Digest([]byte(alias))
	pendingCount(t, s.db, 1, "SELECT count(*) FROM conversion_jobs WHERE hash=? AND failures=1 AND next_run=? AND version!=''", hash, prior)
	if j, err := s.ClaimProbe(ctx); err != nil || j != nil {
		t.Fatal("renaming bypassed infrastructure backoff", j, err)
	}
	if _, err := s.db.Exec("UPDATE conversion_jobs SET next_run=1; UPDATE conversion_first_clock SET retry_at=1"); err != nil {
		t.Fatal(err)
	}
	j, err := s.ClaimProbe(ctx)
	if err != nil || j == nil || j.Hash != hash {
		t.Fatal("deferred current alias did not become claimable", j, err)
	}
	incomplete(*j)
	pendingCount(t, s.db, 1, "SELECT count(*) FROM conversion_first_clock WHERE failures=2 AND retry_at>?", prior)
	raw = alias + "-again"
	commitProbeInputs(t, s, id, raw)
	pendingCount(t, s.db, 1, "SELECT count(*) FROM conversion_jobs WHERE hash=? AND failures=2 AND next_run>?", repair.Digest([]byte(raw)), prior)
	if _, err = s.db.Exec("UPDATE conversion_jobs SET next_run=1; UPDATE conversion_first_clock SET retry_at=1"); err != nil {
		t.Fatal(err)
	}
	j, err = s.ClaimProbe(ctx)
	if err != nil || j == nil {
		t.Fatal(err)
	}
	if err = s.CompleteProbe(ctx, conversionResult(*j, 0, true)); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, 1, "SELECT count(*) FROM conversion_first_assessed WHERE hash=?", repair.Digest([]byte(raw)))
	pendingCount(t, s.db, 0, "SELECT count(*) FROM conversion_first_clock")
}

func TestMigrateOrdinaryClockUsesOnlyWitnessedWorkAndOrdinaryTime(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	src := testSource()
	one, err := s.Save(ctx, "", 0, src)
	if err != nil {
		t.Fatal(err)
	}
	old, alias, pinned, archived := sourceURI(221), sourceURI(221)+"-alias", sourceURI(222), sourceURI(223)
	commitProbeInputs(t, s, one, old, pinned, archived)
	src.URL = "https://example.org/other-clock"
	two, err := s.Save(ctx, "", 0, src)
	if err != nil {
		t.Fatal(err)
	}
	commitProbeInputs(t, s, two, alias)
	commitProbeInputs(t, s, one, old)
	hash := func(raw string) string { return repair.Digest([]byte(raw)) }
	// Recreate a v52 snapshot with two real schedules of one identity, one
	// lawful withdrawn pin without a surviving schedule and a collector-only
	// raw with no remaining ordinary ownership.
	_, err = s.db.Exec(`DROP TRIGGER conversion_first_clock_pin; DROP TRIGGER conversion_first_clock_schedule;
 DROP TRIGGER conversion_first_clock_assessed; DROP VIEW conversion_first_raw_clock; DROP TABLE conversion_first_clock;
 PRAGMA user_version=52;`)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		raw               string
		admitted, started int
	}{{old, 1000, 2000}, {alias, 5000, 6000}} {
		if _, err = s.db.Exec("UPDATE conversion_schedule SET created=?,last_started=? WHERE hash=?", row.admitted, row.started, hash(row.raw)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = s.db.Exec("DELETE FROM conversion_first_backlog WHERE hash=?", hash(archived)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("DELETE FROM conversion_jobs WHERE hash IN(?,?)", hash(archived), hash(pinned)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("UPDATE egress_unique SET created=1"); err != nil {
		t.Fatal(err)
	}
	path, key := filepath.Join(filepath.Dir(s.vault.Directory()), "panel.db"), s.key
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	before := time.Now().UnixMilli()
	reopened, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	pendingCount(t, reopened.db, 1, "SELECT count(*) FROM conversion_first_clock WHERE admitted=1000 AND last_started=6000")
	pendingCount(t, reopened.db, 2, "SELECT count(*) FROM conversion_schedule WHERE hash IN(?,?) AND created=1000 AND last_started=6000", hash(old), hash(alias))
	pendingCount(t, reopened.db, 1, "SELECT count(*) FROM conversion_first_clock WHERE identity IN(SELECT identity FROM egress_owners WHERE hash=?) AND admitted>=?", hash(pinned), before)
	pendingCount(t, reopened.db, 1, "SELECT count(*) FROM egress_owners WHERE hash=?", hash(archived))
	pendingCount(t, reopened.db, 0, "SELECT count(*) FROM conversion_first_clock WHERE identity IN(SELECT identity FROM egress_owners WHERE hash=?)", hash(archived))
	if err := reopened.migrateV53(); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, reopened.db, 2, "SELECT count(*) FROM conversion_first_clock")
}
