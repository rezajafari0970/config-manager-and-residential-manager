package panel

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/compat"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/convert"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/probe"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/target"
	"strings"
	"time"
)

func (s *Store) migrateV20() error {
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var version int
	if e = tx.QueryRow("PRAGMA user_version").Scan(&version); e != nil {
		return e
	}
	if version >= 20 {
		return nil
	}
	if _, e = tx.Exec("CREATE TABLE IF NOT EXISTS conversion_evidence(hash TEXT PRIMARY KEY REFERENCES conversion_jobs(hash) ON DELETE CASCADE,metadata TEXT NOT NULL)"); e != nil {
		return e
	}
	rows, e := tx.Query("SELECT name,sql FROM sqlite_master WHERE type='view' AND sql IS NOT NULL")
	if e != nil {
		return e
	}
	type view struct{ name, q string }
	views := []view{}
	for rows.Next() {
		var v view
		if e = rows.Scan(&v.name, &v.q); e != nil {
			rows.Close()
			return e
		}
		views = append(views, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	replace := strings.NewReplacer("xray-26.7.28.template.v5", convert.Version)
	for _, v := range views {
		q := replace.Replace(v.q)
		if q != v.q {
			if _, e = tx.Exec("DROP VIEW " + v.name + ";" + q); e != nil {
				return e
			}
		}
	}
	if _, e = tx.Exec("UPDATE conversion_jobs SET token='',lease_until=0,state='queued',next_run=0 WHERE version!=?", convert.Version); e != nil {
		return e
	}
	if _, e = tx.Exec("PRAGMA user_version=20"); e != nil {
		return e
	}
	return tx.Commit()
}
func receipt(r probe.Result) ([]byte, error) {
	if len(r.Evidence) > 32 {
		return nil, ErrInvalid
	}
	for key, status := range r.Evidence {
		if !safeCode(key) || !safeCode(status) || len(status) > 80 {
			return nil, ErrInvalid
		}
	}
	var changes []compat.Change
	if len(r.Candidate) > 0 {
		_, changes, _ = compat.ApplyJSON(r.Candidate)
	}
	engine := r.Engine
	if engine == "" {
		engine = "xray"
	}
	family := compat.Family(r.Candidate)
	var targetInfo any = target.Pinned()
	bundled := "cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1"
	if engine == "sing-box" {
		targetInfo = map[string]string{"id": "sing-box-1.14.4"}
		bundled = ""
		var root map[string]any
		if json.Unmarshal(r.Candidate, &root) == nil {
			for _, field := range []string{"outbounds", "endpoints"} {
				if nodes, ok := root[field].([]any); ok && len(nodes) > 0 {
					if ob, ok := nodes[0].(map[string]any); ok {
						if typ, ok := ob["type"].(string); ok {
							family = "sing-box." + typ
						}
					}
				}
			}
		}
	}
	return json.Marshal(map[string]any{"engine": engine, "family": family, "target": targetInfo, "pipeline": r.Version, "driver_version": compat.Version, "raw_sha256": r.Hash, "candidate_sha256": r.SHA256, "runtime_sha256": r.RuntimeSHA256, "core_sha256": r.CoreSHA256, "bundled_core_sha256": bundled, "changes": changes, "checks": r.Evidence, "attempts": r.Attempts, "rule": r.Rule, "code": r.Code, "tested": time.Now().UnixMilli(), "android": "not_run", "http3": r.Evidence["http3"]})
}
func saveConversionEvidence(ctx context.Context, tx *sql.Tx, r probe.Result) error {
	b, e := receipt(r)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, "INSERT INTO conversion_evidence VALUES(?,?) ON CONFLICT(hash) DO UPDATE SET metadata=excluded.metadata", r.Hash, string(b))
	return e
}
