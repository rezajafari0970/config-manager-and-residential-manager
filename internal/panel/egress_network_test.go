package panel

import (
	"context"
	"encoding/json"
	"slices"
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
	var last egress.Job
	complete := func(kind string) {
		t.Helper()
		if _, err := s.db.Exec("UPDATE egress_jobs SET next_run=0"); err != nil {
			t.Fatal(err)
		}
		job, err := s.ClaimEgress(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if job == nil {
			// This reducer also accepts operator-issued fixture leases after the
			// finite automatic confirmation allowance is spent. Exercise the
			// independent proof-recovery reducer with a fixture lease.
			pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_network_results WHERE held=1")
			job = &last
			job.Token = randomToken()
			now := egress.Now()
			if _, err = s.db.Exec("UPDATE egress_jobs SET token=?,lease_until=?,claimed_at=? WHERE hash=?", job.Token, now+120000, now, job.Hash); err != nil {
				t.Fatal(err)
			}
		}
		last = *job
		report := syntheticEgress(*job)
		for i := range report.Samples {
			x := &report.Samples[i]
			if !x.ActualAds {
				continue
			}
			firstFlow := x.Variant == "template" && x.Domain == egress.Domains[0]
			secondFlow := x.Variant == "raw" && x.Domain == egress.Domains[1]
			legacyFlow := x.Variant == "template" && x.Domain == egress.Domains[2]
			switch kind {
			case "unknown":
				x.Network = nil
			case "hosting":
				if firstFlow || legacyFlow {
					x.Network.Kind, x.Network.Provider, x.Network.ASN = "hosting", "vultr", 20473
				}
			case "hosting-other":
				if secondFlow {
					x.Network.Kind, x.Network.Provider, x.Network.ASN = "hosting", "vultr", 20473
				}
			case "unrelated":
				if firstFlow {
					x.Network = nil
				}
			case "missing-legacy":
				if legacyFlow {
					x.Network = nil
				}
			case "scoped":
				if !firstFlow && !secondFlow && !legacyFlow {
					x.Network = nil
				}
			}
		}
		if err = s.CompleteEgress(ctx, egress.Completion{Job: *job, Report: report}); err != nil {
			t.Fatal(err)
		}
	}
	complete("unknown")
	check(true)
	complete("hosting")
	check(false)
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_work")
	// A v45 hit identified only its first adverse flow. Reopening must retain
	// the hold even as other fresh routes resume publication immediately.
	if _, err = s.db.Exec(`UPDATE egress_network_results SET last_adverse=json_remove(last_adverse,'$.hosting_flows','$.hosting_asns');
 UPDATE egress_network_results SET summary=last_adverse; PRAGMA user_version=45`); err != nil {
		t.Fatal(err)
	}
	if err = s.migrateV46(); err != nil {
		t.Fatal(err)
	}
	check(false)
	complete("hosting-other")
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
	complete("unrelated")
	complete("unrelated")
	check(false)
	complete("missing-legacy")
	complete("missing-legacy")
	check(false)
	complete("scoped")
	check(false)
	var provider string
	var held, rounds int
	if err = s.db.QueryRow("SELECT held,clean_rounds,json_extract(last_adverse,'$.provider') FROM egress_network_results").Scan(&held, &rounds, &provider); err != nil || held != 1 || rounds != 1 || provider != "vultr" {
		t.Fatal("lost prior hosting observation", held, rounds, provider, err)
	}
	complete("scoped")
	check(true)
	if _, err = s.db.Exec("UPDATE egress_network_results SET candidate_hash='other',valid_until=1"); err != nil {
		t.Fatal(err)
	}
	check(true)
	// The confirmed route, health and country still govern every public feed.
	deadline := egress.Now() + 12345
	if _, err = s.db.Exec("UPDATE egress_jobs SET valid_until=?", deadline); err != nil {
		t.Fatal(err)
	}
	entries, _, err := egressSnapshot(ctx, s.db)
	if err != nil || len(entries) != 1 || entries[0].Until != deadline {
		t.Fatal("incorrect route cutoff", entries, err)
	}
	if _, err = s.db.Exec("UPDATE egress_jobs SET valid_until=1"); err != nil {
		t.Fatal(err)
	}
	for _, uri := range feeds {
		if res := exportRequest(t, app.Handler(), "GET", uri); res.Code != 503 {
			t.Fatal("expired route published", res.Code)
		}
	}
}

func TestEgressNetworkMigrationRestoresFreshLegacySplitWithoutReset(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	newExportSource(t, s, "migration", sourceURI(852))
	job, err := s.ClaimEgress(ctx)
	if err != nil || job == nil {
		t.Fatal(err)
	}
	report := syntheticEgress(*job)
	report.Samples = slices.DeleteFunc(report.Samples, func(sample egress.Sample) bool {
		return sample.ActualAds && !slices.Contains(egress.Profiles()[0].Domains, sample.Domain)
	})
	for i := range report.Samples {
		report.Samples[i].Network = nil
	}
	if err = s.CompleteEgress(ctx, egress.Completion{Job: *job, Report: report}); err != nil {
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
		if err = s.migrateV46(); err != nil {
			t.Fatal(err)
		}
		if err = s.reconcileEgressNetworkPolicy(); err != nil {
			t.Fatal(err)
		}
		var split, published, blocked, scheduled, knownCountry int
		if err = s.db.QueryRow(`SELECT (SELECT count(*) FROM egress_eligible),(SELECT count(*) FROM egress_export_eligible),
 (SELECT count(*) FROM input_blocked),(SELECT count(*) FROM egress_jobs WHERE hash=? AND tested>0 AND next_run=0),
 (SELECT count(*) FROM egress_geo_results WHERE complete=1)`, job.Hash).Scan(&split, &published, &blocked, &scheduled, &knownCountry); err != nil || split != 1 || published != 1 || blocked != 0 || scheduled != 1 || knownCountry != 1 {
			t.Fatal(split, published, blocked, scheduled, knownCountry, err)
		}
	}
}

func TestV45SharedHostingReceiptCorrectsOnlyOriginalMatchingHold(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	for i, name := range []string{"bound", "unbound", "different-provider"} {
		newExportSource(t, s, name, sourceURI(854+i))
		job, err := s.ClaimEgress(ctx)
		if err != nil || job == nil {
			t.Fatal(err)
		}
		r := partialProfileReport(*job)
		old := egress.NetworkVerdict{Version: egress.NetworkVersion, State: "hosting", Reason: "ads_hosting_exit", Provider: "amazon", ASN: 16509}
		for k := range r.Samples {
			x := &r.Samples[k]
			if !x.ActualAds {
				continue
			}
			if slices.Contains(egress.Profiles()[0].Domains, x.Domain) {
				x.Network = nil
				continue
			}
			x.Network.Kind, x.Network.Provider, x.Network.ASN, x.Network.Source = "hosting", "amazon", 16509, x.Source
			if old.Domain == "" {
				old.Domain, old.Variant, old.Family = x.Domain, x.Variant, x.Family
			}
		}
		if err = s.CompleteEgress(ctx, egress.Completion{Job: *job, Report: r}); err != nil {
			t.Fatal(err)
		}
		if i == 2 {
			old.Provider, old.ASN = "vultr", 20473
		}
		previous, _ := json.Marshal(old)
		_, err = s.db.Exec(`UPDATE egress_network_results SET state='hosting',reason='ads_hosting_exit',last_adverse=?,summary=?,held=1,checked_at=checked_at+? WHERE hash=?`, string(previous), string(previous), i%2, job.Hash)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec("PRAGMA user_version=45"); err != nil {
		t.Fatal(err)
	}
	if err := s.migrateV46(); err != nil {
		t.Fatal(err)
	}
	var route, held, published int
	if err := s.db.QueryRow(`SELECT (SELECT count(*) FROM egress_eligible),(SELECT count(*) FROM egress_network_results WHERE held=1),(SELECT count(*) FROM egress_export_eligible)`).Scan(&route, &held, &published); err != nil || route != 3 || held != 2 || published != 1 {
		t.Fatal("legacy shared and unmatched hold", route, held, published, err)
	}
}
