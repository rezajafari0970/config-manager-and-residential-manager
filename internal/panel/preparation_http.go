package panel

import (
	"context"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/convert"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
	"io"
	"net/http"
	"strconv"
)

type preparedEntry struct {
	ID, Hash, Candidate, Engine, Code string
	Healthy                           bool
}

func preparedEntries(ctx context.Context, q conversionQuerier, source, engine string) ([]preparedEntry, error) {
	now := readStamp(ctx)
	query := `WITH choices AS (SELECT a.id,m.raw_hash,CASE WHEN r.connection='passed' AND r.core='passed' AND r.version=p.version AND r.valid_until>CAST(unixepoch('subsec')*1000 AS INTEGER) THEN r.candidate_hash ELSE p.candidate_hash END AS candidate_hash,p.engine,p.code,
 coalesce(r.connection='passed' AND r.core='passed' AND r.version=p.version AND r.candidate_hash!='' AND r.valid_until>?,0) AS healthy,
 row_number() OVER(PARTITION BY a.id ORDER BY (p.candidate_hash!='') DESC,p.prepared DESC,m.raw_hash) AS choice
 FROM memberships m JOIN artifacts a ON a.id=m.artifact_id JOIN sources s ON s.id=m.source_id JOIN template_preparations p ON p.hash=m.raw_hash LEFT JOIN conversion_results r ON r.hash=m.raw_hash
 WHERE a.expires>? AND s.enabled=1 AND p.version=? AND p.engine=? AND NOT EXISTS(SELECT 1 FROM config_controls c WHERE c.id=a.id AND c.expires>?) ` + inputOutputGate
	args := []any{now, now, convert.Version, engine, now}
	if source != "" {
		query += " AND m.source_id=?"
		args = append(args, source)
	}
	query += `) SELECT id,raw_hash,candidate_hash,engine,code,healthy FROM choices WHERE choice=1 ORDER BY id`
	rows, e := q.QueryContext(ctx, query, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []preparedEntry{}
	for rows.Next() {
		var v preparedEntry
		if e = rows.Scan(&v.ID, &v.Hash, &v.Candidate, &v.Engine, &v.Code, &v.Healthy); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Server) preparedExport(w http.ResponseWriter, r *http.Request) {
	source, engine := r.URL.Query().Get("source"), r.URL.Query().Get("engine")
	if engine == "" {
		engine = "xray"
	}
	if engine != "xray" && engine != "sing-box" {
		failure(w, ErrInvalid)
		return
	}
	if _, e := s.store.exportSourceName(r.Context(), source); e != nil {
		failure(w, e)
		return
	}
	entries, e := preparedEntries(r.Context(), s.store.reader(), source, engine)
	if e != nil {
		failure(w, e)
		return
	}
	healthy := r.URL.Query().Get("healthy") == "1"
	single := r.URL.Query().Get("single") == "1"
	scope := source + "/" + engine + "/" + strconv.FormatBool(healthy)
	unlock, e := s.store.lockRotation(r.Context(), "prepared/"+scope)
	if e != nil {
		failure(w, e)
		return
	}
	defer unlock()
	cursor := ""
	if single {
		_ = s.store.reader().QueryRowContext(r.Context(), "SELECT cursor FROM prepared_rotation WHERE scope=?", scope).Scan(&cursor)
	}
	eligible := []preparedEntry{}
	for _, v := range entries {
		if v.Candidate != "" && (!healthy || v.Healthy) && (r.URL.Query().Get("id") == "" || r.URL.Query().Get("id") == v.ID) {
			eligible = append(eligible, v)
		}
	}
	if single && len(eligible) > 0 {
		chosen := eligible[0]
		for _, v := range eligible {
			if v.ID > cursor {
				chosen = v
				break
			}
		}
		eligible = []preparedEntry{chosen}
	}
	out, e := newExportSpool()
	if e != nil {
		failure(w, e)
		return
	}
	defer out.Close()
	out.array = !single && engine == "xray"
	written := []preparedEntry{}
	for _, v := range eligible {
		body, err := s.store.vault.Open(v.Candidate)
		if err != nil {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(body, repair.MaxBytes+1))
		body.Close()
		if err != nil || repair.Digest(b) != v.Candidate {
			continue
		}
		if e = out.Line(b); e != nil {
			failure(w, e)
			return
		}
		written = append(written, v)
	}
	if single && len(written) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// Recheck current ownership, controls and health under the writer before
	// publishing a snapshot. A concurrent deletion must never leak stale output.
	tx, e := s.store.db.BeginTx(r.Context(), nil)
	if e != nil {
		failure(w, e)
		return
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(r.Context(), "INSERT INTO prepared_rotation VALUES(?,'') ON CONFLICT DO NOTHING", scope); e != nil {
		failure(w, e)
		return
	}
	current, e := preparedEntries(r.Context(), tx, source, engine)
	if e != nil {
		failure(w, e)
		return
	}
	live := map[string]preparedEntry{}
	for _, v := range current {
		live[v.ID] = v
	}
	for _, v := range written {
		n, ok := live[v.ID]
		if !ok || n.Hash != v.Hash || n.Candidate != v.Candidate || (healthy && !n.Healthy) {
			failure(w, ErrConflict)
			return
		}
	}
	if single {
		if _, e = tx.ExecContext(r.Context(), "UPDATE prepared_rotation SET cursor=? WHERE scope=?", written[0].ID, scope); e != nil {
			failure(w, e)
			return
		}
	}
	if e = tx.Commit(); e != nil {
		failure(w, e)
		return
	}
	if e = out.Rewind(); e != nil {
		failure(w, e)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if single || out.array {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	}
	w.Header().Set("X-Config-Count", strconv.Itoa(len(written)))
	w.Header().Set("X-Config-Engine", engine)
	w.Header().Set("X-Verification-Scope", "prepared-only; connection-not-verified")
	if healthy {
		w.Header().Set("X-Verification-Scope", "exact-core; https-dns-payload-verified; android-not-run")
	}
	_, _ = out.WriteTo(w)
}
