package panel

import (
	"context"
	"encoding/json"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/networkclass"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
	"io"
	"log"
	"sync"
	"time"
)

func (s *Store) migrateV42() error {
	var v int
	if e := s.db.QueryRow("PRAGMA user_version").Scan(&v); e != nil {
		return e
	}
	if v >= 42 {
		return nil
	}
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	_, e = tx.Exec(`CREATE TABLE IF NOT EXISTS network_classifications(raw_hash TEXT PRIMARY KEY,datacenter TEXT NOT NULL,cdn TEXT NOT NULL,reason TEXT NOT NULL,evidence TEXT NOT NULL,checked INTEGER NOT NULL,expires INTEGER NOT NULL,next_run INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS network_due ON network_classifications(next_run);
 CREATE TABLE IF NOT EXISTS network_cache(key TEXT PRIMARY KEY,data BLOB,expires INTEGER NOT NULL,refresh INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS network_rotation_state(scope TEXT PRIMARY KEY,cycle INTEGER NOT NULL DEFAULT 0);
 CREATE TABLE IF NOT EXISTS network_rotation_queue(scope TEXT NOT NULL REFERENCES network_rotation_state(scope) ON DELETE CASCADE,position INTEGER NOT NULL,candidate_hash TEXT NOT NULL,PRIMARY KEY(scope,position),UNIQUE(scope,candidate_hash));
 PRAGMA user_version=42;`)
	if e != nil {
		return e
	}
	return tx.Commit()
}

type networkCache struct{ s *Store }

// Versioned derived metadata. Existing array evidence is still readable by old
// binaries and is refreshed once in the background; no health receipt changes.
type networkEvidence struct {
	Version   int                        `json:"version"`
	Addresses []networkclass.Evidence    `json:"addresses"`
	Family    networkclass.AddressFamily `json:"ip_family"`
}

func (c networkCache) Get(ctx context.Context, key string) (networkclass.Record, error) {
	var r networkclass.Record
	e := c.s.reader().QueryRowContext(ctx, "SELECT data,expires,refresh FROM network_cache WHERE key=?", key).Scan(&r.Data, &r.Expires, &r.Refresh)
	return r, e
}
func (c networkCache) Put(ctx context.Context, key string, r networkclass.Record) error {
	release, e := c.s.operations.acquire(ctx, false)
	if e != nil {
		return e
	}
	defer release()
	_, e = c.s.db.ExecContext(ctx, "INSERT INTO network_cache VALUES(?,?,?,?) ON CONFLICT(key) DO UPDATE SET data=excluded.data,expires=excluded.expires,refresh=excluded.refresh", key, []byte(r.Data), r.Expires, r.Refresh)
	return e
}
func (s *Store) saveNetwork(ctx context.Context, hash string, r networkclass.Result) error {
	b, _ := json.Marshal(networkEvidence{Version: 1, Addresses: r.Evidence, Family: r.Family})
	refresh := r.Expires
	if r.Family.Expires > 0 {
		refresh = min(refresh, r.Family.Expires)
	}
	release, e := s.operations.acquire(ctx, false)
	if e != nil {
		return e
	}
	defer release()
	_, e = s.db.ExecContext(ctx, `INSERT INTO network_classifications VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(raw_hash) DO UPDATE SET datacenter=excluded.datacenter,cdn=excluded.cdn,reason=excluded.reason,evidence=excluded.evidence,checked=excluded.checked,expires=excluded.expires,next_run=excluded.next_run`, hash, r.Datacenter, r.CDN, r.Reason, string(b), r.Checked, r.Expires, max(time.Now().Add(30*time.Second).UnixMilli(), refresh-15000))
	return e
}

const networkLive = `SELECT DISTINCT m.raw_hash FROM memberships m JOIN artifacts a ON a.id=m.artifact_id JOIN sources s ON s.id=m.source_id WHERE s.enabled=1 AND a.expires>CAST(unixepoch('subsec')*1000 AS INTEGER) AND NOT EXISTS(SELECT 1 FROM config_controls c WHERE c.id=a.id AND c.expires>CAST(unixepoch('subsec')*1000 AS INTEGER))` + inputOutputGate

// Two bounded I/O workers, no proxy processes or requests to config endpoints.
// Shutdown waits for workers before the Store is closed. Cache failures are
// retried; startup and ordinary output delivery never depend on remote feeds.
func (s *Store) RunNetworkClassifier(ctx context.Context) {
	classifier := networkclass.New(networkCache{s})
	familyCtx, stopFamilies := context.WithCancel(ctx)
	familiesDone := make(chan struct{})
	go func() {
		defer close(familiesDone)
		s.runNetworkFamilies(familyCtx, classifier)
	}()
	defer func() { stopFamilies(); <-familiesDone }()
	jobs := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for hash := range jobs {
				sub, cancel := context.WithTimeout(ctx, 30*time.Second)
				body, e := s.vault.Open(hash)
				if e == nil {
					b, err := io.ReadAll(io.LimitReader(body, repair.MaxBytes+1))
					body.Close()
					if err == nil && repair.Digest(b) == hash && len(b) <= repair.MaxBytes {
						result := classifier.Classify(sub, b)
						// A slow ASN lookup must not discard an already determined
						// literal family just because the I/O deadline elapsed.
						persist, stop := context.WithTimeout(ctx, 5*time.Second)
						err = s.saveNetwork(persist, hash, result)
						stop()
						if err != nil && ctx.Err() == nil {
							log.Print("network classification persistence will retry")
						}
					}
				}
				cancel()
			}
		}()
	}
	defer func() { close(jobs); wg.Wait() }()
	lastCleanup := time.Time{}
	for ctx.Err() == nil {
		classifier.Refresh(ctx)
		rows, e := s.workerReader().QueryContext(ctx, `SELECT live.raw_hash FROM (`+networkLive+`) live LEFT JOIN network_classifications n ON n.raw_hash=live.raw_hash WHERE coalesce(n.next_run,0)<=? ORDER BY coalesce(n.next_run,0),live.raw_hash LIMIT 32`, time.Now().UnixMilli())
		hashes := []string{}
		if e == nil {
			for rows.Next() {
				var h string
				if rows.Scan(&h) == nil {
					hashes = append(hashes, h)
				}
			}
			e = rows.Err()
			rows.Close()
		}
		if e != nil && ctx.Err() == nil {
			log.Print("network classification queue will retry")
		}
		for _, h := range hashes {
			select {
			case jobs <- h:
			case <-ctx.Done():
				return
			}
		}
		if time.Since(lastCleanup) > time.Hour {
			release, err := s.operations.acquire(ctx, false)
			if err == nil {
				_, _ = s.db.ExecContext(ctx, `DELETE FROM network_cache WHERE expires<? AND key NOT LIKE 'feed/%'`, time.Now().Add(-24*time.Hour).UnixMilli())
				_, _ = s.db.ExecContext(ctx, `DELETE FROM network_classifications WHERE checked<? AND raw_hash NOT IN (SELECT raw_hash FROM memberships)`, time.Now().Add(-24*time.Hour).UnixMilli())
				release()
			}
			lastCleanup = time.Now()
		}
		wait := time.Second
		if len(hashes) < 32 {
			wait = 10 * time.Second
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

type networkEntry struct {
	Conversion
	IPFamily     string `json:"ip_family"`
	Datacenter   string `json:"datacenter"`
	CDN          string `json:"cdn"`
	Reason       string `json:"reason"`
	Checked      int64  `json:"checked"`
	ClassExpires int64  `json:"classification_expires"`
}

func networkEntries(ctx context.Context, q readQuerier, axis, group string) ([]networkEntry, error) {
	cs, e := queryConversions(ctx, q, 0, true)
	if e != nil {
		return nil, e
	}
	rows, e := q.QueryContext(ctx, "SELECT raw_hash,datacenter,cdn,reason,checked,expires,evidence FROM network_classifications")
	if e != nil {
		return nil, e
	}
	classes := map[string]networkEntry{}
	now := readStamp(ctx)
	for rows.Next() {
		var h string
		var evidence string
		var n networkEntry
		if e = rows.Scan(&h, &n.Datacenter, &n.CDN, &n.Reason, &n.Checked, &n.ClassExpires, &evidence); e != nil {
			rows.Close()
			return nil, e
		}
		var record networkEvidence
		n.IPFamily = "unknown"
		if json.Unmarshal([]byte(evidence), &record) == nil && record.Version == 1 {
			n.IPFamily = record.Family.Current(now)
		}
		classes[h] = n
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	out := []networkEntry{}
	for _, c := range cs {
		n, ok := classes[c.Hash]
		if !ok {
			n.IPFamily = "unknown"
		}
		if !ok || n.ClassExpires <= now {
			n.Datacenter = "unknown"
			n.CDN = "unknown"
			n.Reason = "pending_or_expired"
		}
		n.Conversion = c
		if axis == "" || n.group(axis) == group {
			out = append(out, n)
		}
	}
	return out, nil
}

func (n networkEntry) group(axis string) string {
	switch axis {
	case "datacenter":
		return n.Datacenter
	case "cdn":
		return n.CDN
	case "ip-family":
		return n.IPFamily
	default:
		return ""
	}
}
