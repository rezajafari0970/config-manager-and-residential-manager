package panel

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"sync"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/networkclass"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
)

// Family refresh preserves provider evidence and scheduling, including legacy
// array evidence. Only this derived metadata is written; no probe is queued.
func (s *Store) saveNetworkFamily(ctx context.Context, hash string, family networkclass.AddressFamily) error {
	f, _ := json.Marshal(family)
	b, _ := json.Marshal(networkEvidence{Version: 1, Addresses: []networkclass.Evidence{}, Family: family})
	release, err := s.operations.acquire(ctx, false)
	if err != nil {
		return err
	}
	defer release()
	_, err = s.db.ExecContext(ctx, `INSERT INTO network_classifications VALUES(?,'unknown','unknown','pending_or_expired',?,0,0,0)
ON CONFLICT(raw_hash) DO UPDATE SET evidence=json_set(
CASE WHEN json_type(network_classifications.evidence)='array'
THEN json_object('addresses',json(network_classifications.evidence)) ELSE network_classifications.evidence END,
'$.version',1,'$.ip_family',json(?))`, hash, string(b), string(f))
	return err
}

func (s *Store) networkFamilyBatch(ctx context.Context, classifier *networkclass.Classifier) (int, error) {
	rows, err := s.workerReader().QueryContext(ctx, `SELECT live.raw_hash FROM (`+networkLive+`) live
LEFT JOIN network_classifications n ON n.raw_hash=live.raw_hash
WHERE coalesce(json_extract(n.evidence,'$.version'),0)!=1
OR coalesce(json_extract(n.evidence,'$.ip_family.id'),'')=''
OR (coalesce(json_extract(n.evidence,'$.ip_family.expires'),0)>0 AND json_extract(n.evidence,'$.ip_family.expires')<=?)
ORDER BY coalesce(json_extract(n.evidence,'$.ip_family.expires'),0),live.raw_hash LIMIT 64`, time.Now().UnixMilli())
	if err != nil {
		return 0, err
	}
	var hashes []string
	for rows.Next() {
		var hash string
		if err = rows.Scan(&hash); err != nil {
			break
		}
		hashes = append(hashes, hash)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return 0, err
	}
	var wg sync.WaitGroup
	for slot := 0; slot < 2; slot++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := slot; i < len(hashes) && ctx.Err() == nil; i += 2 {
				hash := hashes[i]
				family := networkclass.AddressFamily{ID: "unknown", Reason: "original_blob_unavailable", Expires: time.Now().Add(time.Minute).UnixMilli()}
				sub, cancel := context.WithTimeout(ctx, 5*time.Second)
				body, openErr := s.vault.Open(hash)
				if openErr == nil {
					b, readErr := io.ReadAll(io.LimitReader(body, repair.MaxBytes+1))
					body.Close()
					if readErr == nil && len(b) <= repair.MaxBytes && repair.Digest(b) == hash {
						family = classifier.ClassifyFamily(sub, b)
					}
				}
				cancel()
				persist, stop := context.WithTimeout(ctx, 5*time.Second)
				if err := s.saveNetworkFamily(persist, hash, family); err != nil && ctx.Err() == nil {
					log.Print("address family persistence will retry")
				}
				stop()
			}
		}()
	}
	wg.Wait()
	return len(hashes), nil
}

// Independent, bounded DNS-only work must not wait behind external ASN/feed
// requests. Both paths share the same resolver cache and join on shutdown.
func (s *Store) runNetworkFamilies(ctx context.Context, classifier *networkclass.Classifier) {
	for ctx.Err() == nil {
		count, err := s.networkFamilyBatch(ctx, classifier)
		if err != nil && ctx.Err() == nil {
			log.Print("address family queue will retry")
		}
		wait := time.Second
		if count < 64 {
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
