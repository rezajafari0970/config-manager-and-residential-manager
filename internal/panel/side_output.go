package panel

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/side"
)

const sideVerificationScope = "side-all-services"
const sideRotationScope = "side/accepted-v1"

type sideOutputModule struct{ s *Server }

func (m sideOutputModule) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/side", m.summary)
	mux.HandleFunc("GET /api/side/reviews", m.reviews)
	mux.HandleFunc("GET /subscription/side/{token}/{file}", m.export)
}

func (m sideOutputModule) links() map[string]string {
	links := make(map[string]string, 3)
	for _, file := range []string{"configs.json", "next.json", "raw.txt"} {
		links[file] = m.s.origin + "/subscription/side/" + m.s.store.digest("side-subscription-v1", file) + "/" + file
	}
	return links
}

func (m sideOutputModule) summary(w http.ResponseWriter, r *http.Request) {
	ctx, closeSnapshot, err := m.s.store.readSnapshot(r.Context())
	if err != nil {
		failure(w, err)
		return
	}
	defer closeSnapshot()
	counts, err := m.s.store.SideCounts(ctx)
	if err != nil {
		failure(w, err)
		return
	}
	window, err := readSideThroughput(ctx, m.s.store.read(ctx))
	if err != nil {
		failure(w, err)
		return
	}
	var status string
	var heartbeat int64
	if err := m.s.store.read(ctx).QueryRowContext(ctx, "SELECT status,heartbeat FROM side_worker WHERE id=1").Scan(&status, &heartbeat); err != nil {
		failure(w, err)
		return
	}
	respond(w, http.StatusOK, map[string]any{"counts": counts, "throughput": window, "now": readStamp(ctx), "links": m.links(),
		"worker": map[string]any{"status": status, "heartbeat": heartbeat}})

}

func sideTemplateEntries(ctx context.Context, q readQuerier) ([]networkEntry, error) {
	return sideExportEntries(ctx, q, true)
}

func sideExportEntries(ctx context.Context, q readQuerier, templatesOnly bool) ([]networkEntry, error) {
	query := "SELECT identity,raw_hash,candidate_hash FROM side_export_inputs"
	if templatesOnly {
		query += " WHERE engine='xray'"
	}
	rows, err := q.QueryContext(ctx, query+" ORDER BY identity")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []networkEntry
	for rows.Next() {
		var e networkEntry
		if err := rows.Scan(&e.ID, &e.Hash, &e.CandidateHash); err != nil {
			return nil, err
		}
		e.Available = true
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func (m sideOutputModule) export(w http.ResponseWriter, r *http.Request) {
	file := r.PathValue("file")
	if (file != "configs.json" && file != "next.json" && file != "raw.txt") ||
		!equal(r.PathValue("token"), m.s.store.digest("side-subscription-v1", file)) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Disposition", "inline")
	w.Header().Set("X-Verification-Scope", sideVerificationScope)
	if file == "raw.txt" {
		m.s.verifiedRaw(w, r, rawScope{side: true})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if file == "next.json" {
		// Link previews and metadata requests never consume a turn.
		if r.Method == http.MethodHead {
			return
		}
		if strings.Contains(strings.ToLower(r.Header.Get("Sec-Purpose")+" "+r.Header.Get("Purpose")), "prefetch") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		m.next(w, r)
		return
	}
	for range 2 {
		if m.writeArray(w, r) || r.Context().Err() != nil {
			return
		}
	}
	w.Header().Set("Retry-After", "1")
	http.Error(w, "subscription changed; retry", http.StatusServiceUnavailable)
}

func (m sideOutputModule) next(w http.ResponseWriter, r *http.Request) {
	group := exportRound{entries: sideTemplateEntries, key: func(c Conversion) string { return c.ID }}
	item, err := m.s.store.nextExportRound(r.Context(), sideRotationScope, group, m.s.store.sideTemplateBytes)
	if err != nil {
		http.Error(w, "verified configuration temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	if item == nil {
		w.Header().Set("X-Config-Count", "0")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("X-Config-Count", "1")
	w.Header().Set("X-Export-Cycle", strconv.FormatInt(item.Cycle, 10))
	w.Header().Set("X-Content-SHA256", item.Conversion.CandidateHash)
	_, _ = w.Write(item.Bytes)
}

func (m sideOutputModule) writeArray(w http.ResponseWriter, r *http.Request) bool {
	ctx := r.Context()
	entries, err := sideTemplateEntries(ctx, m.s.store.reader())
	if err != nil {
		failure(w, err)
		return true
	}
	out, err := newExportSpool()
	if err != nil {
		failure(w, err)
		return true
	}
	defer out.Close()
	out.array = true
	for _, e := range entries {
		if ctx.Err() != nil {
			return true
		}
		b, err := m.s.store.sideTemplateBytes(ctx, e.Conversion)
		if errors.Is(err, ErrConflict) {
			return false
		}
		if err != nil {
			http.Error(w, "verified configuration temporarily unavailable", http.StatusServiceUnavailable)
			return true
		}
		if err := out.Line(b); err != nil {
			failure(w, err)
			return true
		}
	}
	current, err := m.s.store.verifiedSnapshotCurrent(ctx, rawScope{sideTemplates: true}, entries)
	if err != nil {
		failure(w, err)
		return true
	}
	if !current {
		return false
	}
	if err := out.Rewind(); err != nil {
		failure(w, err)
		return true
	}
	w.Header().Set("X-Config-Count", strconv.Itoa(len(entries)))
	w.Header().Set("X-Content-SHA256", out.Hash())
	if r.Method != http.MethodHead {
		_, _ = out.WriteTo(w)
	}
	return true
}

// Restore exactly the previously tested bytes if their encrypted file was lost
// or corrupted. A changed template never inherits old measurements. Callers
// recheck membership after blob I/O, including after this repair.
func (s *Store) sideTemplateBytes(ctx context.Context, c Conversion) ([]byte, error) {
	b, err := s.conversionBytes(c)
	if err == nil || ctx.Err() != nil {
		return b, err
	}
	// Only rebuild a file for a still-publishable, exact-byte receipt; do not
	// pin or update its validity, and do not revive a disabled protocol.
	var current bool
	if err := s.reader().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM side_export_inputs
		WHERE identity=? AND raw_hash=? AND candidate_hash=? AND engine='xray')`, c.ID, c.Hash, c.CandidateHash).Scan(&current); err != nil {
		return nil, err
	}
	if !current {
		return nil, ErrConflict
	}
	raw, err := s.sideRaw(c.Hash)
	if err != nil {
		return nil, err
	}
	for _, candidate := range side.Prepare(raw).Candidates {
		if candidate.SHA256 != c.CandidateHash {
			continue
		}
		ref, err := s.vault.Put(ctx, bytes.NewReader(candidate.Config))
		if err != nil {
			return nil, err
		}
		defer s.vault.Release(ref.Hash)
		if ref.Hash != c.CandidateHash {
			return nil, ErrInvalid
		}
		return s.conversionBytes(c)
	}
	return nil, ErrNotFound
}
