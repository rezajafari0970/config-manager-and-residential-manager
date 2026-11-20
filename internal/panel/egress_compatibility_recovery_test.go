package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func TestCompatibilityReceiptsDoNotReopenAfterUpgradeOrRefetch(t *testing.T) {
	for _, mode := range []string{"current", "returned", "pinned", "still_unsupported", "previous_observation", "disabled", "operator", "interrupted", "disable_during_lease", "missing_driver"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			s := testStore(t)
			raw := sourceURI(184)
			if mode == "still_unsupported" {
				raw = "unsupported-fixture://not-an-operational-route"
			}
			id, err := s.Save(ctx, "", 0, testSource())
			if err != nil {
				t.Fatal(err)
			}
			commitProbeInputs(t, s, id, raw)
			first, err := s.ClaimEgress(ctx)
			if err != nil || first == nil {
				t.Fatal("original receipt lease", err)
			}
			exec := func(q string, args ...any) {
				t.Helper()
				if _, err := s.db.Exec(q, args...); err != nil {
					t.Fatal(err)
				}
			}
			now := egress.Now()
			r := egress.Report{Version: egress.Version, Hash: first.Hash, Started: now, Finished: now, Code: "driver_unavailable"}
			if mode == "previous_observation" {
				r.Attempts = []egress.Attempt{{Core: "xray", Code: "test_failed"}}
			}
			oldReport, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			d := egress.Evaluate(r, egress.Plan{}, first.Hash, now)
			oldDecision, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			exec(`UPDATE egress_jobs SET token='',lease_until=0,first_completed=1,tested=?,state='UNSUPPORTED',reason='driver_unavailable',report=?,decision=?,next_run=? WHERE hash=?`, now, string(oldReport), string(oldDecision), now+3600000, first.Hash)
			exec("INSERT INTO egress_events(hash,at,state,reason,first_result_scope) VALUES(?,?,'UNSUPPORTED','driver_unavailable','current')", first.Hash, now)
			exec("UPDATE egress_metrics SET first_assessments=1,completed=1")
			// Empty outcome rows are created by an ordinary completed assessment.
			exec("INSERT INTO egress_health VALUES(?,'unknown',?,0,'{}')", first.Hash, now)
			exec("INSERT INTO egress_geo_results VALUES(?,0,'route_unqualified',?,0,'{}')", first.Hash, now)
			if mode == "pinned" {
				exec("INSERT INTO conversion_first_backlog(source_id,identity,hash) SELECT ?,identity,hash FROM egress_unique", id)
			}
			if mode == "returned" || mode == "pinned" {
				exec("DELETE FROM memberships")
			}
			if mode == "disabled" {
				exec("UPDATE sources SET enabled=0 WHERE id=?", id)
			}
			if mode == "operator" {
				exec("INSERT INTO config_controls SELECT identity,'disabled',1,? FROM egress_unique", now+3600000)
			}
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
			if mode == "returned" {
				commitProbeInputs(t, s, id, raw)
			}
			if mode == "disabled" {
				exec("UPDATE sources SET enabled=1 WHERE id=?", id)
			}
			exec("UPDATE egress_jobs SET next_run=0")
			job, err := s.ClaimEgress(ctx)
			if err != nil || job != nil {
				t.Fatal("measured identity received another first grant", err)
			}
			pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_compatibility_queue")
			pendingCount(t, s.db, 1, "SELECT first_assessments FROM egress_metrics")
			var got []byte
			if err = s.db.QueryRow("SELECT report FROM egress_jobs WHERE hash=?", first.Hash).Scan(&got); err != nil || !bytes.Equal(got, oldReport) {
				t.Fatal("original receipt changed", err)
			}
		})
	}
}
