package panel

import (
	"context"
	"testing"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func TestEgressHostingWithdrawsResidentialFeedsOnlyAndRequiresFreshRecovery(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	raw := sourceURI(851)
	newExportSource(t, s, "primary", raw)
	newExportSource(t, s, "alias", raw+"-cosmetic")
	app, err := NewServer(s, "http://127.0.0.1:18191")
	if err != nil {
		t.Fatal(err)
	}
	feeds := egressModule{app}.links()
	check := func(published bool) {
		t.Helper()
		var split, ordinaryBlocked, unique, displayed int
		err := s.db.QueryRow(`SELECT (SELECT count(*) FROM egress_eligible),(SELECT count(*) FROM input_blocked),
 (SELECT count(*) FROM egress_unique),(SELECT count(*) FROM egress_export_eligible)`).Scan(&split, &ordinaryBlocked, &unique, &displayed)
		if err != nil || split != 1 || ordinaryBlocked != 0 || unique != 1 || (displayed == 1) != published {
			t.Fatalf("scope: split=%d ordinary_blocked=%d identities=%d exports=%d err=%v", split, ordinaryBlocked, unique, displayed, err)
		}
		for _, uri := range feeds {
			res := exportRequest(t, app.Handler(), "GET", uri)
			if published && (res.Code != 200 || res.Header().Get("X-Config-Count") != "1") || !published && res.Code != 503 {
				t.Fatalf("unexpected export: %d", res.Code)
			}
		}
	}
	complete := func(kind string) {
		t.Helper()
		if _, err := s.db.Exec("UPDATE egress_jobs SET next_run=0"); err != nil {
			t.Fatal(err)
		}
		job, err := s.ClaimEgress(ctx)
		if err != nil || job == nil {
			t.Fatal("lost renewal", err)
		}
		report := syntheticEgress(*job)
		for i := range report.Samples {
			x := &report.Samples[i]
			if !x.ActualAds {
				continue
			}
			switch kind {
			case "unknown":
				x.Network = nil
			case "hosting":
				x.Network.Kind, x.Network.Provider, x.Network.ASN = "hosting", "vultr", 20473
			}
		}
		if err = s.CompleteEgress(ctx, egress.Completion{Job: *job, Report: report}); err != nil {
			t.Fatal(err)
		}
	}
	complete("access")
	check(true)
	complete("hosting")
	check(false)
	var identity, hash string
	var created int64
	if err = s.db.QueryRow("SELECT identity,hash,created FROM egress_unique").Scan(&identity, &hash, &created); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("DELETE FROM egress_unique WHERE identity=?", identity); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("INSERT INTO egress_unique VALUES(?,?,?)", identity, hash, created); err != nil {
		t.Fatal(err)
	}
	complete("unknown")
	check(false)
	complete("access")
	check(false)
	var provider string
	var held, rounds int
	if err = s.db.QueryRow("SELECT held,clean_rounds,json_extract(last_adverse,'$.provider') FROM egress_network_results").Scan(&held, &rounds, &provider); err != nil || held != 1 || rounds != 1 || provider != "vultr" {
		t.Fatal("lost prior hosting observation", held, rounds, provider, err)
	}
	complete("access")
	check(true)
	if _, err = s.db.Exec("UPDATE egress_network_results SET candidate_hash='other'"); err != nil {
		t.Fatal(err)
	}
	check(false)
	complete("access")
	// The final export snapshot carries the actual publication deadline, even
	// when the base route and all memberships remain fresh for much longer.
	deadline := egress.Now() + 12345
	if _, err = s.db.Exec("UPDATE egress_network_results SET valid_until=?", deadline); err != nil {
		t.Fatal(err)
	}
	entries, _, err := egressSnapshot(ctx, s.db)
	if err != nil || len(entries) != 1 || entries[0].Until != deadline {
		t.Fatal("incorrect network cutoff", entries, err)
	}
	if _, err = s.db.Exec("UPDATE egress_network_results SET valid_until=1"); err != nil {
		t.Fatal(err)
	}
	check(false)
}

func TestEgressNetworkMigrationHidesLegacySplitWithoutReset(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	newExportSource(t, s, "migration", sourceURI(852))
	job, err := s.ClaimEgress(ctx)
	if err != nil || job == nil {
		t.Fatal(err)
	}
	if err = s.CompleteEgress(ctx, egress.Completion{Job: *job, Report: syntheticEgress(*job)}); err != nil {
		t.Fatal(err)
	}
	// Reproduce the schema44 eligibility chain and a previously published member.
	var geo string
	if err = s.db.QueryRow("SELECT replace(sql,'FROM egress_network_eligible ','FROM egress_eligible ') FROM sqlite_master WHERE name='egress_geo_eligible'").Scan(&geo); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("DROP VIEW egress_geo_eligible;" + geo + "; DROP VIEW egress_network_eligible; DROP TRIGGER egress_network_representative_removed; DROP TABLE egress_network_results; DELETE FROM metadata WHERE key='ads-exit-network-policy'; PRAGMA user_version=44"); err != nil {
		t.Fatal(err)
	}
	var before int
	if err = s.db.QueryRow("SELECT count(*) FROM egress_export_eligible").Scan(&before); err != nil || before != 1 {
		t.Fatal("expected legacy publication", before, err)
	}
	for range 2 {
		if err = s.migrateV45(); err != nil {
			t.Fatal(err)
		}
		if err = s.reconcileEgressNetworkPolicy(); err != nil {
			t.Fatal(err)
		}
		var split, published, blocked, scheduled, knownCountry int
		if err = s.db.QueryRow(`SELECT (SELECT count(*) FROM egress_eligible),(SELECT count(*) FROM egress_export_eligible),
 (SELECT count(*) FROM input_blocked),(SELECT count(*) FROM egress_jobs WHERE hash=? AND tested>0 AND next_run=0),
 (SELECT count(*) FROM egress_geo_results WHERE complete=1)`, job.Hash).Scan(&split, &published, &blocked, &scheduled, &knownCountry); err != nil || split != 1 || published != 0 || blocked != 0 || scheduled != 1 || knownCountry != 1 {
			t.Fatal(split, published, blocked, scheduled, knownCountry, err)
		}
	}
}
