package panel

import (
	"bytes"
	"context"
	"database/sql"
	"io"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/collect"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/protocolpolicy"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
)

type firstRawAlias struct {
	hash, identity, kind string
	size                 int64
}

// Each candidate must still have a committed, enabled source for these exact
// bytes. An earlier staged sighting does not provide custody of a replacement.
const firstAliasOwners = ` FROM egress_unique u
 JOIN memberships m ON m.artifact_id=u.identity AND m.raw_hash!=u.hash
 JOIN sources src ON src.id=m.source_id AND src.enabled=1
 JOIN egress_owners o ON o.hash=m.raw_hash AND o.identity=u.identity AND o.source=m.source_id
 JOIN egress_jobs a ON a.hash=m.raw_hash AND a.size=m.size AND a.kind=m.kind
 WHERE u.hash=?1 AND a.state='PENDING' AND a.token='' AND a.paused=0
 AND a.tested=0 AND a.first_completed=0 AND a.ever_accepted=0 AND a.decision='{}'
 AND a.candidate_hash='' AND a.valid_until=0 AND a.deep_completed=0
 AND (a.reason!='first_raw_replaced' OR a.last_seen>a.next_run)`

// Rotate a small verification window on repeated grants. Missing/corrupt alias
// files cannot permanently conceal a later readable source.
func (s *Store) readFirstAlias(ctx context.Context, j egress.Job) (*firstRawAlias, error) {
	rows, err := s.workerReader().QueryContext(ctx, `WITH available AS (
 SELECT DISTINCT m.raw_hash AS hash,u.identity,m.kind,m.size`+firstAliasOwners+`
 AND m.size>0 AND m.size<=?2 AND EXISTS(SELECT 1 FROM egress_jobs old WHERE old.hash=?1
 AND old.revision=?3 AND old.token=?4 AND old.lease_until>?5 AND old.paused=0 AND old.state='PENDING'
 AND old.tested=0 AND old.first_completed=0 AND old.ever_accepted=0)), candidates AS (
 SELECT *,row_number() OVER (ORDER BY hash)-1 AS pos,count(*) OVER () AS n FROM available)
 SELECT hash,identity,kind,size FROM candidates ORDER BY (pos+n-
 (SELECT ((attempts-1)*4)%n FROM egress_jobs WHERE hash=?1))%n LIMIT 4`, j.Hash, repair.MaxBytes, j.Revision, j.Token, egress.Now())
	if err != nil {
		return nil, err
	}
	var candidates []firstRawAlias
	for rows.Next() {
		var a firstRawAlias
		if err = rows.Scan(&a.hash, &a.identity, &a.kind, &a.size); err != nil {
			rows.Close()
			return nil, err
		}
		candidates = append(candidates, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, a := range candidates {
		f, err := s.vault.Open(a.hash)
		if err != nil {
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(f, a.size+1))
		f.Close()
		if err != nil || int64(len(raw)) != a.size || egress.Hash(raw) != a.hash || protocolpolicy.Disabled(a.kind, raw) ||
			collect.Fingerprint(raw, true, a.kind, a.hash) != a.identity {
			continue
		}
		ref, err := s.vault.Put(ctx, bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		if ref.Hash != a.hash {
			s.vault.Release(ref.Hash)
			continue
		}
		return &a, nil // Pinned through the completion commit.
	}
	return nil, nil
}

// This runs in the writer transaction after the missing first preflight releases
// its lease. Never transport a decision or an adverse history to different raw.
func replaceMissingFirst(ctx context.Context, tx *sql.Tx, old string, a *firstRawAlias, now int64) error {
	var allowed bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1`+firstAliasOwners+`
 AND m.raw_hash=?2 AND u.identity=?3 AND m.size=?4 AND m.kind=?5
 AND EXISTS(SELECT 1 FROM egress_jobs j WHERE j.hash=u.hash AND j.reason='input_unavailable'
 AND j.state='PENDING' AND j.token='' AND j.paused=0 AND j.tested=0 AND j.first_completed=0
 AND j.deep_completed=0 AND j.ever_accepted=0 AND j.decision='{}' AND j.candidate_hash='' AND j.valid_until=0)
 AND NOT EXISTS(SELECT 1 FROM input_exclusions WHERE identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM config_controls WHERE id=u.identity AND expires>?6)
 AND NOT EXISTS(SELECT 1 FROM egress_iran_guard WHERE identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_network_results WHERE identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_network_review WHERE identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_owners own JOIN egress_jobs j ON j.hash=own.hash WHERE own.identity=u.identity
 AND (j.first_completed!=0 OR j.tested!=0 OR j.ever_accepted!=0 OR j.paused!=0 OR j.state='DELETED'
 OR EXISTS(SELECT 1 FROM egress_settlements t WHERE t.hash=j.hash)
 OR EXISTS(SELECT 1 FROM egress_residential_history h WHERE h.hash=j.hash)
 OR EXISTS(SELECT 1 FROM egress_health h WHERE h.hash=j.hash)
 OR EXISTS(SELECT 1 FROM egress_geo_results g WHERE g.hash=j.hash)
 OR EXISTS(SELECT 1 FROM egress_retirements r WHERE r.hash=j.hash)
 OR EXISTS(SELECT 1 FROM egress_first_history h WHERE h.hash=j.hash AND h.phase='completed')))
 AND NOT EXISTS(SELECT 1 FROM egress_events WHERE hash IN(SELECT hash FROM egress_owners WHERE identity=?3))
 AND NOT EXISTS(SELECT 1 FROM egress_run_members WHERE (status='completed' OR settled_at>0)
 AND hash IN(SELECT hash FROM egress_owners WHERE identity=?3))
 AND NOT EXISTS(SELECT 1 FROM egress_run_members oldrun JOIN egress_run_members newrun ON newrun.run=oldrun.run
 WHERE oldrun.run=(SELECT max(id) FROM egress_runs) AND oldrun.hash=u.hash AND oldrun.status='pending'
 AND newrun.hash=a.hash))`, old, a.hash, a.identity, a.size, a.kind, now).Scan(&allowed)
	if err != nil || !allowed {
		return err
	}
	// The backlog references egress_unique(hash) directly. Defer its FK only
	// to COMMIT so both hashes change atomically without firing delete triggers.
	if _, err = tx.ExecContext(ctx, "PRAGMA defer_foreign_keys=ON"); err != nil {
		return err
	}
	for _, query := range []string{
		"UPDATE egress_unique SET hash=?2 WHERE hash=?1",
		"UPDATE egress_first_backlog SET hash=?2 WHERE hash=?1",
		"UPDATE egress_run_members SET hash=?2 WHERE hash=?1 AND run=(SELECT max(id) FROM egress_runs) AND status='pending'",
		"UPDATE egress_first_history SET phase='cancelled' WHERE hash=?1 AND phase NOT IN('completed','cancelled')",
		// Reconsider the old raw only after a subsequent source observation.
		// Disk flapping alone cannot bounce the identity between two hashes.
		"UPDATE egress_jobs SET revision=revision+1,reason='first_raw_replaced',next_run=max(last_seen,?3) WHERE hash=?1",
		"UPDATE egress_jobs SET next_run=0 WHERE hash=?2",
	} {
		if _, err = tx.ExecContext(ctx, query, old, a.hash, now); err != nil {
			return err
		}
	}
	return nil
}
