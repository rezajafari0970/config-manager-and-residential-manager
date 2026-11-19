package panel

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
)

type outputModule struct{ s *Server }

func (m outputModule) Register(mux *http.ServeMux) {
	s := m.s
	mux.HandleFunc("GET /api/repairs/{id}", s.repairReport)
	mux.HandleFunc("GET /output/repaired/{id}", s.repaired)
	mux.HandleFunc("POST /api/configs/batch", s.configBatch)
	mux.HandleFunc("GET /output/raw/{id}", s.raw)
	mux.HandleFunc("GET /output/raw.txt", s.rawAll)
	mux.HandleFunc("GET /output/archive.zip", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/output/raw.txt", http.StatusPermanentRedirect)
	})
}
func (s *Server) raw(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		failure(w, ErrNotFound)
		return
	}
	s.verifiedRaw(w, r, rawScope{id: id})
}

func (s *Server) response(w http.ResponseWriter, r *http.Request) {
	source := r.PathValue("id")
	if _, err := s.store.exportSourceName(r.Context(), source); err != nil {
		failure(w, err)
		return
	}
	// Source archives can contain pending inputs. Reconstruct public downloads
	// from the current verified members belonging to the requested source.
	s.verifiedRaw(w, r, rawScope{source: source})
}

func (s *Server) rawAll(w http.ResponseWriter, r *http.Request) {
	s.verifiedRaw(w, r, rawScope{})
}

type rawScope struct {
	source, id, axis, group string
}

func (s *Store) verifiedRawEntries(ctx context.Context, q readQuerier, scope rawScope) ([]networkEntry, error) {
	if scope.axis != "" {
		all, err := s.networkEntries(ctx, q, scope.axis, scope.group)
		return healthyNetworkEntries(all, readStamp(ctx)), err
	}
	rows, err := querySourceIdentityConversions(ctx, q, scope.source, scope.id, 0, true)
	if err != nil {
		return nil, err
	}
	var eligible []networkEntry
	for _, c := range rows {
		if c.Healthy(readStamp(ctx)) {
			eligible = append(eligible, networkEntry{Conversion: c})
		}
	}
	return eligible, nil
}

func (s *Server) verifiedRaw(w http.ResponseWriter, r *http.Request, scope rawScope) {
	for range 2 {
		if s.tryVerifiedRaw(w, r, scope) || r.Context().Err() != nil {
			return
		}
	}
	w.Header().Set("Retry-After", "1")
	http.Error(w, "raw membership changed; retry", http.StatusServiceUnavailable)
}

func (s *Server) tryVerifiedRaw(w http.ResponseWriter, r *http.Request, scope rawScope) bool {
	ctx := r.Context()
	snapshot, done, err := s.store.readSnapshot(ctx)
	if err != nil {
		failure(w, err)
		return true
	}
	entries, err := s.store.verifiedRawEntries(snapshot, s.store.read(snapshot), scope)
	done()
	if err != nil {
		failure(w, err)
		return true
	}
	if len(entries) == 0 {
		rawEmpty(w, scope)
		return true
	}
	spool, err := newExportSpool()
	if err != nil {
		failure(w, err)
		return true
	}
	defer spool.Close()
	writer := io.MultiWriter(spool.file, spool.digest)
	size := 0
	delivered := make([]networkEntry, 0, len(entries))
	for _, n := range entries {
		if ctx.Err() != nil {
			return true
		}
		body, err := s.store.openExportBlob(n.Hash)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			http.Error(w, "verified input unavailable; retry", 503)
			return true
		}
		b, err := io.ReadAll(io.LimitReader(body, repair.MaxBytes+1))
		body.Close()
		if err != nil || len(b) > repair.MaxBytes || repair.Digest(b) != n.Hash {
			http.Error(w, "invalid input; retry", 503)
			return true
		}
		if len(delivered) > 0 {
			if _, err = writer.Write([]byte{'\n'}); err != nil {
				failure(w, err)
				return true
			}
			size++
		}
		delivered = append(delivered, n)
		size += len(b)
		if size > 256<<20 {
			http.Error(w, "raw output size limit", 503)
			return true
		}
		if _, err = writer.Write(b); err != nil {
			failure(w, err)
			return true
		}
	}
	if len(delivered) == 0 {
		rawEmpty(w, scope)
		return true
	}
	if scope.axis != "" {
		if _, err = writer.Write([]byte{'\n'}); err != nil {
			failure(w, err)
			return true
		}
		size++
	}
	current, err := s.store.verifiedSnapshotCurrent(ctx, scope, delivered)
	if err != nil {
		failure(w, err)
		return true
	}
	if !current {
		return false
	}
	if err = spool.Rewind(); err != nil {
		failure(w, err)
		return true
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "inline")
	w.Header().Set("Content-Length", strconv.Itoa(size))
	w.Header().Set("X-Content-SHA256", spool.Hash())
	w.Header().Set("X-Config-Count", strconv.Itoa(len(delivered)))
	framing := "original-bytes; one-LF-between-members"
	if scope.axis != "" {
		framing += "; final-LF"
	}
	w.Header().Set("X-Raw-Framing", framing)
	w.Header().Set("X-Verification-Scope", "verified-current-source-members")
	if r.Method != http.MethodHead {
		_, _ = spool.WriteTo(w)
	}
	return true
}

func (s *Store) verifiedSnapshotCurrent(ctx context.Context, scope rawScope, delivered []networkEntry) (bool, error) {
	if len(delivered) == 0 {
		return true, nil
	}
	tx, err := s.outputTransaction(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "UPDATE metadata SET value=value WHERE key='key-check'"); err != nil {
		return false, err
	}
	current, err := s.verifiedRawEntries(ctx, tx, scope)
	if err != nil || !networkSnapshotCurrent(delivered, current) {
		return false, err
	}
	return true, tx.Commit()
}

func rawEmpty(w http.ResponseWriter, scope rawScope) {
	w.Header().Set("X-Config-Count", "0")
	if scope.id != "" {
		failure(w, ErrNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
