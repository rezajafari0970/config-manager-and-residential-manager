package panel

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func TestV54RechecksOriginalPositiveAndHostingReceipts(t *testing.T) {
	for _, mode := range []string{"country", "extra-country", "native-hold", "protected-hold", "merged-hold", "missing-original", "wrong-driver", "untouched"} {
		t.Run(mode, func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			id, err := s.Save(ctx, "", 0, testSource())
			if err != nil {
				t.Fatal(err)
			}
			raw := sourceURI(183)
			hosting := mode == "native-hold" || mode == "protected-hold" || mode == "merged-hold" || mode == "missing-original"
			if hosting {
				raw = `{"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":10808}],"outbounds":[{"tag":"upstream","type":"trojan","server":"192.0.2.1","server_port":443,"password":"synthetic","tls":{"enabled":true,"server_name":"example.com"}}],"route":{"final":"upstream"}}`
			}
			commitProbeInputs(t, s, id, raw)
			job, err := s.ClaimEgress(ctx)
			if err != nil || job == nil {
				t.Fatal("first grant", err)
			}
			r := syntheticEgress(*job)
			if hosting {
				r.Core, r.CoreSHA = egress.NativeID, egress.NativeSHA
				for i := range r.Samples {
					sample := &r.Samples[i]
					if sample.ActualAds {
						sample.Network.Kind, sample.Network.Provider, sample.Network.ASN = "hosting", "vultr", 20473
					}
				}
			}
			if err = s.CompleteEgress(ctx, egress.Completion{Job: *job, Report: r}); err != nil {
				t.Fatal(err)
			}
			exec := func(q string, args ...any) {
				t.Helper()
				if _, err := s.db.Exec(q, args...); err != nil {
					t.Fatal(err)
				}
			}
			var until int64
			if err = s.db.QueryRow("SELECT valid_until FROM egress_jobs WHERE hash=?", job.Hash).Scan(&until); err != nil {
				t.Fatal(err)
			}
			if hosting {
				pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_network_results WHERE held=1")
				// V53 accepted any well-formed runtime digest for each native
				// variant. Preserve the old verdict while replaying these actual checks.
				for i := range r.Checks {
					r.Checks[i].RuntimeHash = egress.Hash([]byte("different native runtime"))
				}
				if mode == "protected-hold" {
					exec("INSERT INTO config_controls SELECT identity,'disabled',1,? FROM egress_unique", egress.Now()+3600000)
				}
				if mode == "merged-hold" {
					exec("UPDATE egress_network_results SET last_adverse=json_set(last_adverse,'$.hosting_asns[#]',12345)")
				}
				if mode == "missing-original" {
					if err = os.Remove(filepath.Join(s.vault.Directory(), job.Hash+".blob")); err != nil {
						t.Fatal(err)
					}
				}
			} else if mode == "wrong-driver" {
				r.Core, r.CoreSHA = egress.NativeID, egress.NativeSHA
			} else if mode == "country" || mode == "extra-country" {
				sample := r.Samples[0]
				sample.Geo.Providers = append([]egress.CountryProvider(nil), sample.Geo.Providers...)
				sample.Geo.Country, sample.Geo.Status = "", "country_provider_disagreement"
				sample.Geo.Providers[0].Country = "IR"
				sample.Connection = egress.Hash([]byte("extra connection"))[:32]
				sample.Nonce = sample.Connection
				if mode == "extra-country" {
					sample.Wave = r.Waves + 1
					sample.Geo.Status, sample.Geo.Country = "located", "IE"
					for i := range sample.Geo.Providers {
						sample.Geo.Providers[i].Country = "IE"
					}
					exec("UPDATE egress_geo_results SET summary=json_insert(summary,'$.countries[#]','IE')")
					exec("INSERT INTO egress_countries SELECT hash,'IE',tested,tested FROM egress_jobs")
				}
				r.Samples = append(r.Samples, sample)
			}
			data, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			exec("UPDATE egress_jobs SET report=? WHERE hash=?", string(data), job.Hash)
			exec("PRAGMA user_version=53")
			path, key := filepath.Join(filepath.Dir(s.vault.Directory()), "panel.db"), s.key
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = Open(path, key)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			pendingCount(t, s.db, 1, "SELECT first_completed FROM egress_jobs WHERE hash=?", job.Hash)
			pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_events WHERE hash=?", job.Hash)
			switch mode {
			case "country":
				pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_jobs WHERE state='QUARANTINED' AND valid_until=0 AND next_run=0 AND json_extract(decision,'$.country_conflict')=1")
				pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_geo_eligible")
				pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_iran_guard")
			case "extra-country":
				pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_geo_eligible WHERE valid_until=?", until)
				pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_countries WHERE country='IE'")
				pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_countries WHERE country='TR'")
			case "wrong-driver":
				pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_jobs WHERE valid_until=0 AND next_run=0 AND reason='variant_binding_failed' AND ever_accepted=1")
				pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_export_eligible")
			case "untouched":
				pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_geo_eligible WHERE valid_until=?", until)
			case "protected-hold":
				pendingCount(t, s.db, 1, "SELECT held FROM egress_network_results")
				pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_network_review")
			default:
				wantHeld := 0
				if mode == "merged-hold" || mode == "missing-original" {
					wantHeld = 1
				}
				pendingCount(t, s.db, wantHeld, "SELECT held FROM egress_network_results")
				pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_network_review WHERE attempts=0")
				pendingCount(t, s.db, 0, "SELECT count(*) "+datacenterRejectedFrom)
				pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_export_eligible")
				restore, err := s.ClaimEgress(ctx)
				if err != nil || restore == nil || restore.Hash != job.Hash {
					t.Fatal("missing bounded review", err)
				}
				if err = s.migrateV54(); err != nil {
					t.Fatal(err)
				}
				pendingCount(t, s.db, 1, "SELECT attempts FROM egress_network_review")
			}
		})
	}
}

func TestV54ReceiptRepairScansOnlyActionableIndexes(t *testing.T) {
	s := testStore(t)
	rows, err := s.db.Query("EXPLAIN QUERY PLAN "+receiptRepairCandidates, egress.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var details []string
	for rows.Next() {
		var id, parent, aux int
		var detail string
		if err = rows.Scan(&id, &parent, &aux, &detail); err != nil {
			t.Fatal(err)
		}
		details = append(details, detail)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	plan := strings.Join(details, "\n")
	if !strings.Contains(plan, "egress_network_held") || !strings.Contains(plan, "egress_eligibility") || strings.Contains(plan, "SCAN egress_jobs") {
		t.Fatalf("receipt repair lost its restricted candidate indexes\n%s", plan)
	}
}
