package panel

import (
	"context"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/convert"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/networkclass"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
	"io"
	"net/http"
	"strconv"
	"strings"
)

type preparedEntry struct {
	ID, Hash, Candidate, Engine, Code string
	Healthy                           bool
}

func preparedEntries(ctx context.Context, q conversionQuerier, source, engine string) ([]preparedEntry, error) {
	now := readStamp(ctx)
	query := `WITH choices AS (SELECT a.id,m.raw_hash,CASE WHEN r.connection='passed' AND r.core='passed' AND r.version=p.version AND r.valid_until>CAST(unixepoch('subsec')*1000 AS INTEGER) THEN r.candidate_hash ELSE p.candidate_hash END AS candidate_hash,p.engine,p.code,
 coalesce(r.connection='passed' AND r.core='passed' AND r.version=p.version AND r.candidate_hash!='' AND r.valid_until>?,0) AS healthy,
 row_number() OVER(PARTITION BY a.id ORDER BY coalesce(r.connection='passed' AND r.core='passed' AND r.version=p.version AND r.candidate_hash!='' AND r.valid_until>CAST(unixepoch('subsec')*1000 AS INTEGER),0) DESC,(p.candidate_hash!='') DESC,p.prepared DESC,m.raw_hash) AS choice
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
	for range 2 {
		if s.tryPreparedExport(w, r) || r.Context().Err() != nil {
			return
		}
	}
	w.Header().Set("Retry-After", "1")
	failure(w, ErrConflict)
}

// Rebuild a concurrently revoked snapshot once, before any response bytes or
// rotation cursor are committed. Each attempt closes its spool and transaction.
func (s *Server) tryPreparedExport(w http.ResponseWriter, r *http.Request) (complete bool) {
	complete = true
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
	axis, group := r.URL.Query().Get("network_axis"), r.URL.Query().Get("network_group")
	if axis != "" && !networkclass.ValidGroup(axis, group) {
		failure(w, ErrInvalid)
		return
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Sec-Purpose")+" "+r.Header.Get("Purpose")), "prefetch") {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	entries, e := s.store.scopedPreparedEntries(r.Context(), s.store.reader(), source, engine, axis, group)
	if e != nil {
		failure(w, e)
		return
	}
	healthy := true // Public output always requires current exact-byte connection proof.
	single := r.URL.Query().Get("single") == "1"
	scope := source + "/" + engine + "/" + strconv.FormatBool(healthy) + "/" + axis + "/" + group
	unlock, e := s.store.lockRotation(r.Context(), "prepared/"+scope)
	if e != nil {
		failure(w, e)
		return
	}
	defer unlock()
	cursor := ""
	var cycle int64
	if single {
		_ = s.store.reader().QueryRowContext(r.Context(), "SELECT cursor,cycle FROM prepared_rotation WHERE scope=?", scope).Scan(&cursor, &cycle)
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
		if cursor == "" || chosen.ID <= cursor {
			cycle++
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
		body, err := s.store.openExportBlob(v.Candidate)
		if err != nil {
			http.Error(w, "verified template unavailable; retry", 503)
			return
		}
		b, err := io.ReadAll(io.LimitReader(body, repair.MaxBytes+1))
		body.Close()
		if err != nil || repair.Digest(b) != v.Candidate {
			http.Error(w, "verified template invalid; retry", 503)
			return
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
	if _, e = tx.ExecContext(r.Context(), "INSERT INTO prepared_rotation(scope,cursor) VALUES(?,'') ON CONFLICT DO NOTHING", scope); e != nil {
		failure(w, e)
		return
	}
	current, e := s.store.scopedPreparedEntries(r.Context(), tx, source, engine, axis, group)
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
			return false
		}
	}
	if single {
		if _, e = tx.ExecContext(r.Context(), "UPDATE prepared_rotation SET cursor=?,cycle=? WHERE scope=?", written[0].ID, cycle, scope); e != nil {
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
	if single {
		w.Header().Set("X-Export-Cycle", strconv.FormatInt(cycle, 10))
		w.Header().Set("X-Content-SHA256", written[0].Candidate)
	} else {
		w.Header().Set("X-Content-SHA256", out.Hash())
	}
	w.Header().Set("X-Config-Engine", engine)
	w.Header().Set("X-Verification-Scope", "prepared-only; connection-not-verified")
	if healthy {
		w.Header().Set("X-Verification-Scope", "exact-core; https-dns-payload-verified; android-not-run")
	}
	_, _ = out.WriteTo(w)
	return
}

func (s *Store) scopedPreparedEntries(ctx context.Context, q readQuerier, source, engine, axis, group string) ([]preparedEntry, error) {
	var rows []Conversion
	if axis != "" && source == "" {
		// Network entries already contain the same canonical conversion winners.
		// Reuse them instead of reading and ranking every input a second time.
		network, e := s.networkEntries(ctx, q, axis, group)
		if e != nil {
			return nil, e
		}
		for _, n := range network {
			rows = append(rows, n.Conversion)
		}
	} else {
		var e error
		rows, e = querySourceConversions(ctx, q, source, 0, true)
		if e != nil {
			return nil, e
		}
	}
	entries := []preparedEntry{}
	for _, c := range rows {
		if c.Engine == engine && c.Healthy(readStamp(ctx)) {
			entries = append(entries, preparedEntry{ID: c.ID, Hash: c.Hash, Candidate: c.CandidateHash, Engine: c.Engine, Code: c.Code, Healthy: true})
		}
	}
	if axis == "" || source == "" {
		return entries, nil
	}
	network, e := s.networkEntries(ctx, q, axis, group)
	if e != nil {
		return nil, e
	}
	members := map[string]bool{}
	for _, v := range network {
		members[v.ID] = true
	}
	out := []preparedEntry{}
	for _, v := range entries {
		if members[v.ID] {
			out = append(out, v)
		}
	}
	return out, nil
}
