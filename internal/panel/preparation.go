package panel

import (
	"bytes"
	"context"
	"io"
	"log"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/convert"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
)

// Preparation is cheap, deterministic and independent of connectivity. Never
// insert its output into conversion_results or treat it as a health receipt.
func (s *Store) migrateV43() error {
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var v int
	if e = tx.QueryRow("PRAGMA user_version").Scan(&v); e != nil {
		return e
	}
	if v >= 43 {
		return nil
	}
	_, e = tx.Exec(`CREATE TABLE IF NOT EXISTS template_preparations(hash TEXT PRIMARY KEY REFERENCES conversion_jobs(hash) ON DELETE CASCADE,version TEXT NOT NULL,candidate_hash TEXT NOT NULL,code TEXT NOT NULL,engine TEXT NOT NULL,rule TEXT NOT NULL,prepared INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS prepared_candidate ON template_preparations(candidate_hash);
 CREATE TABLE IF NOT EXISTS prepared_rotation(scope TEXT PRIMARY KEY,cursor TEXT NOT NULL);
 PRAGMA user_version=43;`)
	if e != nil {
		return e
	}
	return tx.Commit()
}

// A bounded batch releases the DB reader before decrypting or formatting. Blob
// references are pinned until the ownership-checked insert commits, including GC.
func (s *Store) PrepareBatch(ctx context.Context) (int, error) {
	rows, e := s.workerReader().QueryContext(ctx, `SELECT i.hash FROM conversion_inputs i LEFT JOIN template_preparations p ON p.hash=i.hash LEFT JOIN conversion_jobs j ON j.hash=i.hash LEFT JOIN conversion_results r ON r.hash=i.hash WHERE coalesce(p.version,'')!=? OR (p.code='original_blob_unavailable' AND p.prepared<?) OR (j.token='' AND EXISTS(SELECT 1 FROM conversion_receipts c WHERE c.candidate_hash=p.candidate_hash AND c.version=p.version AND c.engine=p.engine AND c.valid_until>CAST(unixepoch('subsec')*1000 AS INTEGER) AND (coalesce(r.tested,0)<c.tested OR coalesce(r.version,'')!=c.version))) ORDER BY coalesce(p.prepared,0),i.hash LIMIT 128`, convert.Version, time.Now().Add(-time.Minute).UnixMilli())
	if e != nil {
		return 0, e
	}
	var hashes []string
	for rows.Next() {
		var h string
		if e = rows.Scan(&h); e != nil {
			break
		}
		hashes = append(hashes, h)
	}
	e2 := rows.Err()
	rows.Close()
	if e != nil {
		return 0, e
	}
	if e2 != nil {
		return 0, e2
	}
	if len(hashes) == 0 {
		return 0, nil
	}
	type entry struct{ hash, candidate, code, engine, rule string }
	prepared := []entry{}
	defer func() {
		for _, v := range prepared {
			if v.candidate != "" {
				s.vault.Release(v.candidate)
			}
		}
	}()
	for _, h := range hashes {
		if e = ctx.Err(); e != nil {
			return 0, e
		}
		var raw []byte
		body, err := s.vault.Open(h)
		if err == nil {
			raw, err = io.ReadAll(io.LimitReader(body, repair.MaxBytes+1))
			body.Close()
		}
		p := convert.Prepare(raw)
		if err != nil {
			p.Candidates = nil
			p.Code = "original_blob_unavailable"
		}
		candidate := ""
		engine := "xray"
		rule := ""
		if len(p.Candidates) > 0 {
			c := p.Candidates[0]
			rule = c.Rule
			if c.Engine != "" {
				engine = c.Engine
			}
			ref, err := s.vault.Put(ctx, bytes.NewReader(c.Config))
			if err != nil {
				return 0, err
			}
			candidate = ref.Hash
		}

		prepared = append(prepared, entry{h, candidate, p.Code, engine, rule})
	}
	// Recheck current ownership once for the whole bounded batch, under a
	// reserved writer. Re-materializing the UNION view for every row is O(N²)
	// on a populated host and used to dominate preparation latency.
	release, err := s.operations.acquire(ctx, false)
	if err != nil {
		return 0, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "UPDATE conversion_settings SET enabled=enabled WHERE id=1"); err != nil {
		return 0, err
	}
	liveRows, err := tx.QueryContext(ctx, "SELECT i.hash FROM conversion_inputs i JOIN conversion_jobs j ON j.hash=i.hash")
	if err != nil {
		return 0, err
	}
	live := map[string]bool{}
	for liveRows.Next() {
		var h string
		if err = liveRows.Scan(&h); err != nil {
			break
		}
		live[h] = true
	}
	rowErr := liveRows.Err()
	liveRows.Close()
	if err != nil {
		return 0, err
	}
	if rowErr != nil {
		return 0, rowErr
	}
	statement, err := tx.PrepareContext(ctx, `INSERT INTO template_preparations VALUES(?,?,?,?,?,?,?) ON CONFLICT(hash) DO UPDATE SET version=excluded.version,candidate_hash=excluded.candidate_hash,code=excluded.code,engine=excluded.engine,rule=excluded.rule,prepared=excluded.prepared`)
	if err != nil {
		return 0, err
	}
	defer statement.Close()
	now := time.Now().UnixMilli()
	for _, v := range prepared {
		if !live[v.hash] {
			continue
		}
		if _, err = statement.ExecContext(ctx, v.hash, convert.Version, v.candidate, v.code, v.engine, v.rule, now); err != nil {
			return 0, err
		}
		if err = reuseConversionReceipt(ctx, tx, v.hash, v.candidate, v.engine, v.rule, now); err != nil {
			return 0, err
		}
		if v.candidate == "" && v.code != "original_blob_unavailable" {
			// No leased probe is superseded by structural preparation.
			_, err = tx.ExecContext(ctx, `INSERT INTO conversion_results SELECT hash,'',0,'preparation','not_run','not_run',?,?,0,'',?,0 FROM conversion_jobs WHERE hash=? AND token='' ON CONFLICT(hash) DO UPDATE SET candidate_hash='',candidate_size=0,rule='preparation',core='not_run',connection='not_run',code=excluded.code,tested=excluded.tested,valid_until=0,runtime_hash='',version=excluded.version,requires_connection=0`, v.code, now, convert.Version, v.hash)
			if err != nil {
				return 0, err
			}
			if _, err = tx.ExecContext(ctx, "UPDATE conversion_jobs SET state='blocked',version=?,next_run=? WHERE hash=? AND token=''", convert.Version, now+3600000, v.hash); err != nil {
				return 0, err
			}
		}
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}

	return len(hashes), nil
}

func (s *Store) RunPreparer(ctx context.Context) {
	lastCleanup := time.Time{}
	for ctx.Err() == nil {
		if time.Since(lastCleanup) > time.Minute {
			release, e := s.operations.acquire(ctx, false)
			if e == nil {
				_, e = s.db.ExecContext(ctx, "DELETE FROM conversion_receipts WHERE valid_until<=? OR rowid IN(SELECT rowid FROM conversion_receipts ORDER BY tested DESC LIMIT -1 OFFSET 10000)", time.Now().UnixMilli())
				release()
				if e == nil {
					lastCleanup = time.Now()
				}
			}
		}
		n, e := s.PrepareBatch(ctx)
		if e != nil && ctx.Err() == nil {
			log.Print("template preparation will retry")
		}
		delay := time.Second
		if n == 128 && e == nil {
			delay = 20 * time.Millisecond
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
