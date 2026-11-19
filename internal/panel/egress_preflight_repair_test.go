package panel

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func TestV55CorrectsOnlyAuthenticatedAmbiguousPreflight(t *testing.T) {
	for _, mode := range []string{"structural", "active", "dormant", "direct-v53", "canonical", "mixed", "observed", "operator"} {
		t.Run(mode, func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			raw := "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"v":"2","add":"192.0.2.1","port":443,"id":"51c6124e-6166-40ca-a49b-e6c17bd34f43","net":"ws","tls":"auto","scy":"aes-128-gcm","sni":"example.com"}`))
			if mode == "canonical" {
				raw = sourceURI(185)
			}
			id, err := s.Save(ctx, "", 0, testSource())
			if err != nil {
				t.Fatal(err)
			}
			commitProbeInputs(t, s, id, raw)
			first, err := s.ClaimEgress(ctx)
			if err != nil || first == nil {
				t.Fatal("first grant", err)
			}
			h := first.Hash
			exec := func(q string, args ...any) {
				t.Helper()
				if _, err := s.db.Exec(q, args...); err != nil {
					t.Fatal(err)
				}
			}
			marshal := func(v any) string {
				t.Helper()
				b, err := json.Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
				return string(b)
			}
			at := egress.Now() - 600000
			original := egress.Report{Version: egress.Version, Hash: h, Started: at, Finished: at, Code: "driver_unavailable"}
			prior := egress.Evaluate(original, egress.Plan{}, h, at)
			exec(`UPDATE egress_jobs SET token='',lease_until=0,claimed_at=?,first_completed=1,tested=?,state='UNSUPPORTED',reason='driver_unavailable',report=?,decision=?,next_run=? WHERE hash=?`, at, at, marshal(original), marshal(prior), at+3600000, h)
			exec("INSERT INTO egress_events(hash,at,state,reason,first_result_scope) VALUES(?,?,'UNSUPPORTED','driver_unavailable','current')", h, at)
			exec("UPDATE egress_metrics SET first_assessments=1,completed=1")
			if mode != "direct-v53" {
				exec("INSERT INTO egress_compatibility_receipts(hash,identity,tested,report,decision) SELECT hash,identity,?,?,? FROM egress_unique", at, marshal(original), marshal(prior))
				exec("INSERT INTO egress_compatibility_queue VALUES(?,?)", h, id)
			}
			structural := mode == "structural" || mode == "mixed" || mode == "observed" || mode == "operator"
			var rawStructural, rawDecision string
			if structural {
				now := at + 120000
				report := egress.Report{Version: egress.Version, Hash: h, Started: now, Finished: now, Waves: 3, Code: "probe_socks_contract_missing"}
				for _, core := range []string{"xray-26.11.9", "xray-26.10.31", "xray-26.7.28", "xray-26.5.9"} {
					report.Attempts = append(report.Attempts, egress.Attempt{Core: core, Code: report.Code})
				}
				if mode == "mixed" {
					report.Attempts[0].Code = "core_unavailable"
				}
				if mode == "observed" {
					report.Samples = []egress.Sample{{Variant: "raw", Wave: 1, Code: "network_timeout"}}
				}
				rawStructural = marshal(report)
				prior.State, prior.Reason = "UNKNOWN", "exact_variants_incomplete"
				rawDecision = marshal(prior)
				exec(`UPDATE egress_jobs SET claimed_at=?,attempts=2,tested=?,state='UNKNOWN',reason='exact_variants_incomplete',report=?,decision=? WHERE hash=?`, now, now, rawStructural, rawDecision, h)
				exec("INSERT INTO egress_events(hash,at,state,reason) VALUES(?,?,'UNKNOWN','exact_variants_incomplete')", h, now)
				exec("UPDATE egress_metrics SET completed=2")
				if mode == "operator" {
					exec("INSERT INTO config_controls SELECT identity,'disabled',1,? FROM egress_unique", egress.Now()+3600000)
				}
			}
			var active *egress.Job
			if mode == "active" {
				exec("UPDATE egress_jobs SET next_run=0 WHERE hash=?", h)
				active, err = s.ClaimEgress(ctx)
				if err != nil || active == nil {
					t.Fatal("fixture active lease", err)
				}
			}
			if mode == "dormant" {
				exec("DELETE FROM memberships")
				exec("DELETE FROM egress_compatibility_queue")
			}
			if mode == "direct-v53" {
				exec("PRAGMA user_version=53")
			} else {
				exec("PRAGMA user_version=54")
			}
			path, key := filepath.Join(filepath.Dir(s.vault.Directory()), "panel.db"), s.key
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = Open(path, key)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			pendingCount(t, s.db, 1, "SELECT first_assessments FROM egress_metrics")
			corrections := mode != "mixed" && mode != "observed" && mode != "operator" && mode != "canonical"
			if !corrections {
				pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_jobs WHERE reason=?", egress.AmbiguousVMessTransport)
				if mode == "canonical" {
					exec("UPDATE egress_jobs SET next_run=0")
					n, err := s.ClaimEgress(ctx)
					if err != nil || n == nil || n.Hash != h {
						t.Fatal("canonical input lost admission", err)
					}
				}
				return
			}
			wantEvents := 1
			if structural {
				wantEvents = 2
				var saved, old []byte
				if err = s.db.QueryRow("SELECT report,decision FROM egress_compatibility_preflight WHERE hash=?", h).Scan(&saved, &old); err != nil || !bytes.Equal(saved, []byte(rawStructural)) || !bytes.Equal(old, []byte(rawDecision)) {
					t.Fatal("lost historical structural result", err)
				}
			} else {
				pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_compatibility_preflight")
			}
			pendingCount(t, s.db, wantEvents, "SELECT count(*) FROM egress_events")
			pendingCount(t, s.db, wantEvents, "SELECT completed FROM egress_metrics")
			pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_jobs WHERE state='UNSUPPORTED' AND reason=? AND first_completed=1 AND valid_until=0", egress.AmbiguousVMessTransport)
			pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_compatibility_receipts WHERE closed=1 AND report=?", marshal(original))
			if active != nil && s.RenewEgress(ctx, *active) != ErrConflict {
				t.Fatal("old worker still has a lease")
			}
			commitProbeInputs(t, s, id, raw)
			pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_compatibility_queue")
			n, err := s.ClaimEgress(ctx)
			if err != nil || n != nil {
				t.Fatal("new measurement was invented", err)
			}
			if err = s.migrateV55(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
