package panel

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/networkclass"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
	"io"
	"net/http"
	"strconv"
	"strings"
)

type networkModule struct{ s *Server }

func (m networkModule) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/datacenter", m.s.networkSummary)
	mux.HandleFunc("GET /subscription/network/{axis}/{group}/{token}/{file}", m.s.networkExport)
}
func (s *Server) networkURL(axis, group, file string) string {
	return s.origin + "/subscription/network/" + axis + "/" + group + "/" + s.store.digest("network-export-v1", axis+"\x00"+group+"\x00"+file) + "/" + file
}

type networkGroup struct {
	networkclass.Group
	Raw       int    `json:"raw_count"`
	Ready     int    `json:"ready_count"`
	RawURL    string `json:"raw_url"`
	SingleURL string `json:"single_url"`
}

func (s *Server) networkSummary(w http.ResponseWriter, r *http.Request) {
	ctx, done, e := s.store.readSnapshot(r.Context())
	if e != nil {
		failure(w, e)
		return
	}
	defer done()
	entries, e := networkEntries(ctx, s.store.read(ctx), "", "")
	if e != nil {
		failure(w, e)
		return
	}
	groups := func(axis string, items []networkclass.Group) []networkGroup {
		out := []networkGroup{}
		for _, g := range items {
			v := networkGroup{Group: g, RawURL: s.networkURL(axis, g.ID, "raw.txt"), SingleURL: s.networkURL(axis, g.ID, "next.json")}
			seen := map[string]bool{}
			for _, n := range entries {
				id := n.Datacenter
				if axis == "cdn" {
					id = n.CDN
				}
				if id != g.ID {
					continue
				}
				v.Raw++
				if n.Available && !seen[n.CandidateHash] {
					v.Ready++
					seen[n.CandidateHash] = true
				}
			}
			out = append(out, v)
		}
		return out
	}
	pending := 0
	for _, n := range entries {
		if n.Reason == "pending_or_expired" {
			pending++
		}
	}
	feeds := map[string]map[string]int64{}
	for _, f := range networkclass.AllFeeds() {
		var expires, refresh int64
		_ = s.store.read(ctx).QueryRowContext(ctx, "SELECT expires,refresh FROM network_cache WHERE key=?", "feed/"+f.ID).Scan(&expires, &refresh)
		feeds[f.ID] = map[string]int64{"expires": expires, "refresh": refresh}
	}
	respond(w, 200, map[string]any{"datacenters": groups("datacenter", networkclass.Datacenters), "cdns": groups("cdn", networkclass.CDNs), "total": len(entries), "pending": pending, "feeds": feeds, "now": readStamp(ctx)})
}
func (s *Server) networkExport(w http.ResponseWriter, r *http.Request) {
	axis, group, file := r.PathValue("axis"), r.PathValue("group"), r.PathValue("file")
	if !networkclass.ValidGroup(axis, group) || (file != "raw.txt" && file != "next.json") || !equal(r.PathValue("token"), s.store.digest("network-export-v1", axis+"\x00"+group+"\x00"+file)) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "inline")
	w.Header().Set("X-Network-Axis", axis)
	w.Header().Set("X-Network-Group", group)
	if r.Method == http.MethodHead {
		w.WriteHeader(200)
		return
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Sec-Purpose")+" "+r.Header.Get("Purpose")), "prefetch") {
		w.WriteHeader(204)
		return
	}
	if file == "raw.txt" {
		s.networkRaw(w, r, axis, group)
		return
	}
	item, e := s.store.nextNetwork(r.Context(), axis, group)
	if e != nil {
		http.Error(w, "network output temporarily unavailable", 503)
		return
	}
	if item == nil {
		w.Header().Set("X-Config-Count", "0")
		w.WriteHeader(204)
		return
	}
	w.Header().Set("X-Config-Count", "1")
	w.Header().Set("X-Content-SHA256", item.Conversion.CandidateHash)
	w.Header().Set("X-Export-Cycle", strconv.FormatInt(item.Cycle, 10))
	w.Write(item.Bytes)
	w.Write([]byte{'\n'})
}
func networkFingerprint(entries []networkEntry) string {
	type pair struct{ ID, Hash string }
	v := []pair{}
	for _, n := range entries {
		v = append(v, pair{n.ID, n.Hash})
	}
	b, _ := json.Marshal(v)
	return repair.Digest(b)
}

// New arrivals join the next download. Every captured identity and raw body
// must remain eligible in the same group at the final admission point.
func networkSnapshotCurrent(before, current []networkEntry) bool {
	captured := map[string]bool{}
	for _, n := range before {
		captured[n.ID] = true
	}
	retained := []networkEntry{}
	for _, n := range current {
		if captured[n.ID] {
			retained = append(retained, n)
		}
	}
	return networkFingerprint(before) == networkFingerprint(retained)
}

func (s *Server) networkRaw(w http.ResponseWriter, r *http.Request, axis, group string) {
	ctx := r.Context()
	snapshot, done, e := s.store.readSnapshot(ctx)
	if e != nil {
		failure(w, e)
		return
	}
	entries, e := networkEntries(snapshot, s.store.read(snapshot), axis, group)
	done()
	if e != nil {
		failure(w, e)
		return
	}
	if len(entries) == 0 {
		w.Header().Set("X-Config-Count", "0")
		w.WriteHeader(204)
		return
	}
	spool, e := newExportSpool()
	if e != nil {
		failure(w, e)
		return
	}
	defer spool.Close()
	size := 0
	for _, n := range entries {
		if ctx.Err() != nil {
			return
		}
		body, err := s.store.vault.Open(n.Hash)
		if err != nil {
			http.Error(w, "raw body unavailable; retry", 503)
			return
		}
		b, err := io.ReadAll(io.LimitReader(body, repair.MaxBytes+1))
		body.Close()
		size += len(b) + 1
		if err != nil || len(b) > repair.MaxBytes || size > 256<<20 || repair.Digest(b) != n.Hash {
			http.Error(w, "raw body validation failed; retry", 503)
			return
		}
		if e = spool.Line(b); e != nil {
			failure(w, e)
			return
		}
	}
	tx, e := s.store.outputTransaction(ctx)
	if e != nil {
		failure(w, e)
		return
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "UPDATE metadata SET value=value WHERE key='key-check'"); e != nil {
		failure(w, e)
		return
	}
	current, e := networkEntries(ctx, tx, axis, group)
	if e != nil {
		failure(w, e)
		return
	}
	if !networkSnapshotCurrent(entries, current) {
		http.Error(w, "group changed; retry", 503)
		return
	}
	if e = tx.Commit(); e != nil {
		failure(w, e)
		return
	}
	if e = spool.Rewind(); e != nil {
		failure(w, e)
		return
	}
	w.Header().Set("X-Config-Count", strconv.Itoa(len(entries)))
	w.Header().Set("X-Content-SHA256", spool.Hash())
	spool.WriteTo(w)
}

// Network rotations have their own tables and locks; global and per-source
// rounds are not touched. Membership is checked again after vault I/O.
func (s *Store) prepareNetwork(ctx context.Context, axis, group string) (*rotatingConfig, error) {
	scope := axis + "/" + group
	tx, e := s.outputTransaction(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "INSERT INTO network_rotation_state(scope) VALUES(?) ON CONFLICT DO NOTHING", scope); e != nil {
		return nil, e
	}
	entries, e := networkEntries(ctx, tx, axis, group)
	if e != nil {
		return nil, e
	}
	available := map[string]Conversion{}
	ordered := []Conversion{}
	for _, n := range entries {
		if n.Available {
			if _, ok := available[n.CandidateHash]; !ok {
				available[n.CandidateHash] = n.Conversion
				ordered = append(ordered, n.Conversion)
			}
		}
	}
	var cycle int64
	if e = tx.QueryRowContext(ctx, "SELECT cycle FROM network_rotation_state WHERE scope=?", scope).Scan(&cycle); e != nil {
		return nil, e
	}
	rows, e := tx.QueryContext(ctx, "SELECT candidate_hash FROM network_rotation_queue WHERE scope=? ORDER BY position", scope)
	if e != nil {
		return nil, e
	}
	queue := []string{}
	for rows.Next() {
		var hash string
		if e = rows.Scan(&hash); e != nil {
			rows.Close()
			return nil, e
		}
		queue = append(queue, hash)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	for _, hash := range queue {
		if c, ok := available[hash]; ok {
			return &rotatingConfig{Conversion: c, Scope: scope, Cycle: cycle}, tx.Commit()
		}
		if _, e = tx.ExecContext(ctx, "DELETE FROM network_rotation_queue WHERE scope=? AND candidate_hash=?", scope, hash); e != nil {
			return nil, e
		}
	}
	if len(ordered) == 0 {
		return nil, tx.Commit()
	}
	if _, e = tx.ExecContext(ctx, "UPDATE network_rotation_state SET cycle=cycle+1 WHERE scope=?", scope); e != nil {
		return nil, e
	}
	for i, c := range ordered {
		if _, e = tx.ExecContext(ctx, "INSERT INTO network_rotation_queue VALUES(?,?,?)", scope, i, c.CandidateHash); e != nil {
			return nil, e
		}
	}
	return &rotatingConfig{Conversion: ordered[0], Scope: scope, Cycle: cycle + 1}, tx.Commit()
}
func (s *Store) claimNetwork(ctx context.Context, axis, group string, item *rotatingConfig) (bool, error) {
	tx, e := s.outputTransaction(ctx)
	if e != nil {
		return false, e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "UPDATE network_rotation_state SET cycle=cycle WHERE scope=?", item.Scope); e != nil {
		return false, e
	}
	var cycle int64
	var next string
	e = tx.QueryRowContext(ctx, `SELECT cycle,coalesce((SELECT candidate_hash FROM network_rotation_queue WHERE scope=? ORDER BY position LIMIT 1),'') FROM network_rotation_state WHERE scope=?`, item.Scope, item.Scope).Scan(&cycle, &next)
	if e != nil {
		return false, e
	}
	if cycle != item.Cycle || next != item.Conversion.CandidateHash {
		return false, nil
	}
	entries, e := networkEntries(ctx, tx, axis, group)
	if e != nil {
		return false, e
	}
	valid := false
	for _, n := range entries {
		if n.ID == item.Conversion.ID && n.Hash == item.Conversion.Hash && n.Available && n.CandidateHash == next {
			valid = true
			break
		}
	}
	if !valid {
		return false, nil
	}
	if _, e = tx.ExecContext(ctx, "DELETE FROM network_rotation_queue WHERE scope=? AND candidate_hash=?", item.Scope, next); e != nil {
		return false, e
	}
	return true, tx.Commit()
}
func (s *Store) nextNetwork(ctx context.Context, axis, group string) (*rotatingConfig, error) {
	unlock, e := s.lockRotation(ctx, "network/"+axis+"/"+group)
	if e != nil {
		return nil, e
	}
	defer unlock()
	for attempts := 0; attempts < 64; attempts++ {
		item, e := s.prepareNetwork(ctx, axis, group)
		if e != nil || item == nil {
			return nil, e
		}
		item.Bytes, e = s.conversionBytes(item.Conversion)
		if e != nil {
			if e = s.retryConversionBlob(ctx, item.Conversion); e != nil {
				return nil, e
			}
			continue
		}
		claimed, e := s.claimNetwork(ctx, axis, group, item)
		if e != nil {
			return nil, e
		}
		if claimed {
			return item, nil
		}
	}
	return nil, errors.New("group changed repeatedly")
}
