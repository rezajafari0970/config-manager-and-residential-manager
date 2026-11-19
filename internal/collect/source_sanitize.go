package collect

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/blob"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/protocolpolicy"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/transient"
)

type sourceFilterKey struct{}

// A format may recognize a prohibited profile it cannot extract. Its container
// must still be rewritten even when other members can be extracted normally.
func markUnclassified(ctx context.Context) {
	if dirty, ok := ctx.Value(sourceFilterKey{}).(*bool); ok {
		*dirty = true
	}
}

const inspectionSampleSize = 1 << 20

type sourceRecord struct {
	io.ReadSeeker
	sample   []byte
	complete bool
}

type acceptRecord func(context.Context, string, sourceRecord) (bool, error)

// Each callback sees an entire independently rewindable profile. Oversized
// profiles spill to an unlinked file and never pass policy on a prefix alone.
func readSourceRecord(ctx context.Context, r io.Reader, fn func(sourceRecord) error) error {
	r = &contextReader{ctx, r}
	prefix, err := io.ReadAll(io.LimitReader(r, inspectionSampleSize+1))
	if err != nil {
		return err
	}
	if len(prefix) <= inspectionSampleSize {
		return fn(sourceRecord{bytes.NewReader(prefix), prefix, true})
	}
	f, _, err := transient.NewFile()
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(prefix); err != nil {
		return err
	}
	if _, err = io.Copy(f, r); err != nil {
		return err
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return fn(sourceRecord{f, prefix[:inspectionSampleSize], false})
}

// Reinsert a separator only when the preceding decoded member had no newline.
// In particular, embedded newlines in WireGuard and JSON are retained verbatim.
type sourceMembers struct {
	w     *bufio.Writer
	count int
	last  byte
}

func (s *sourceMembers) Write(p []byte) (int, error) {
	if len(p) != 0 {
		s.last = p[len(p)-1]
	}
	return s.w.Write(p)
}
func (s *sourceMembers) append(rec sourceRecord) error {
	if s.count > 0 && s.last != '\n' {
		if err := s.w.WriteByte('\n'); err != nil {
			return err
		}
	}
	s.count++
	if rec.complete {
		_, err := s.Write(rec.sample)
		return err
	}
	if _, err := rec.Seek(0, io.SeekStart); err != nil {
		return err
	}
	_, err := io.Copy(s, rec)
	return err
}

// The acquired source is in an anonymous spool. The original representation is
// retained byte for byte when all its profiles are permitted. For mixed sources
// only the retained members become a durable blob.
func filterSource(ctx context.Context, registry *Registry, vault *blob.Vault, spool *os.File, path string, original blob.Ref, accept acceptRecord) (blob.Ref, bool, error) {
	filtered, _, err := transient.NewFile()
	if err != nil {
		return blob.Ref{}, false, err
	}
	defer filtered.Close()
	members := sourceMembers{w: bufio.NewWriter(filtered)}
	dirty := false
	ctx = context.WithValue(ctx, sourceFilterKey{}, &dirty)
	parseErr := registry.Extract(ctx, path, func(ctx context.Context, r io.Reader, kind string) error {
		if protocolpolicy.DisabledKind(kind) {
			dirty = true
			return nil
		}
		return readSourceRecord(ctx, r, func(rec sourceRecord) error {
			var blocked bool
			if rec.complete {
				blocked = protocolpolicy.Disabled(kind, rec.sample)
			} else {
				blocked, err = protocolpolicy.DisabledReader(kind, rec)
				if err != nil {
					return err
				}
				if _, err = rec.Seek(0, io.SeekStart); err != nil {
					return err
				}
			}
			if blocked {
				dirty = true
				return nil
			}
			if accept != nil {
				keep, err := accept(ctx, kind, rec)
				if err != nil {
					return err
				}
				if !keep {
					dirty = true
					return nil
				}
			}
			return members.append(rec)
		})
	})
	if parseErr != nil {
		if !IsContentError(parseErr) {
			return blob.Ref{}, false, parseErr
		}
		dirty = true
	}
	if err := ctx.Err(); err != nil {
		return blob.Ref{}, false, err
	}
	if dirty {
		if members.count == 0 {
			return blob.Ref{}, true, parseErr
		}
		if err := members.w.Flush(); err != nil {
			return blob.Ref{}, false, err
		}
		spool = filtered
	} else if original.Hash != "" {
		return original, false, nil
	}
	if _, err = spool.Seek(0, io.SeekStart); err != nil {
		return blob.Ref{}, false, err
	}
	ref, err := vault.Put(ctx, &contextReader{ctx, spool})
	if err != nil {
		return blob.Ref{}, false, err
	}
	return ref, dirty, parseErr
}

// SanitizeResponse rewrites historical source archives using the same extraction
// and protocol checks as fresh fetches. A changed, nonempty result is pinned
// until the caller commits the new reference and calls vault.Release.
func SanitizeResponse(ctx context.Context, vault *blob.Vault, original blob.Ref) (blob.Ref, bool, error) {
	r, err := vault.Open(original.Hash)
	if err != nil {
		return blob.Ref{}, false, err
	}
	defer r.Close()
	spool, path, err := transient.NewFile()
	if err != nil {
		return blob.Ref{}, false, err
	}
	defer spool.Close()
	if _, err = io.Copy(spool, &contextReader{ctx, r}); err != nil {
		return blob.Ref{}, false, err
	}
	ref, changed, err := filterSource(ctx, NewRegistry(), vault, spool, path, original, nil)
	if IsContentError(err) {
		err = nil // The archive only retains completely parsed allowed members.
	}
	return ref, changed, err
}
