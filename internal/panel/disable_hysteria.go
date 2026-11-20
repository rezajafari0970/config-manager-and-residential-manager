package panel

import (
	"database/sql"
	"io"
	"log"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/protocolpolicy"
)

// Reconcile before any API or worker is admitted. Scan only referenced immutable
// inputs and derived candidates, including Residential identities without a source.
// Mixed subscription archives are sanitized separately before this pass.
func (s *Store) reconcileDisabledProtocols() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT hash,max(kind),max(previously_disabled) FROM (
 SELECT refs.*,0 AS previously_disabled FROM (SELECT hash,kind FROM artifacts
 UNION ALL SELECT raw_hash,kind FROM memberships
 UNION ALL SELECT raw_hash,kind FROM side_jobs WHERE state IN('accepted','pending') AND expires>CAST(unixepoch('subsec')*1000 AS INTEGER)
 UNION ALL SELECT candidate_hash,'' FROM side_jobs WHERE state='accepted' AND expires>CAST(unixepoch('subsec')*1000 AS INTEGER)
 UNION ALL SELECT hash,kind FROM staged
 UNION ALL SELECT hash,kind FROM egress_inventory
 UNION ALL SELECT candidate_hash,'' FROM egress_inventory WHERE candidate_hash!=''
 UNION ALL SELECT candidate_hash,'' FROM repairs WHERE candidate_hash!=''
 UNION ALL SELECT candidate_hash,'' FROM template_preparations WHERE candidate_hash!=''
 UNION ALL SELECT candidate_hash,'' FROM conversion_results WHERE candidate_hash!=''
 UNION ALL SELECT candidate_hash,'' FROM conversion_receipts WHERE valid_until>CAST(unixepoch('subsec')*1000 AS INTEGER)
 ) AS refs
 UNION ALL SELECT hash,'',1 FROM egress_jobs WHERE reason='protocol_disabled' AND state!='DELETED'
 ) WHERE hash!='' GROUP BY hash`)
	if err != nil {
		return err
	}
	var disabled []string
	for rows.Next() {
		var hash, kind string
		var previouslyDisabled bool
		if err := rows.Scan(&hash, &kind, &previouslyDisabled); err != nil {
			rows.Close()
			return err
		}
		if previouslyDisabled || protocolpolicy.DisabledKind(kind) {
			disabled = append(disabled, hash)
			continue
		}
		blocked, err := s.inspectProtocolBlob(hash)
		if err != nil {
			// Missing or corrupt bytes cannot be published. If restored, their
			// first read still requires positive admission by openExportBlob.
			continue
		}
		if blocked {
			disabled = append(disabled, hash)
		} else {
			s.allowedProtocols.add(hash)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(disabled) == 0 {
		return err
	}
	if err = deactivateProtocolHashes(tx, disabled); err != nil {
		return err
	}
	return tx.Commit()
}

// Drain the vault even if parsing stopped early. The final encrypted chunk
// verifies the immutable content hash and catches interrupted reads.
func (s *Store) inspectProtocolBlob(hash string) (bool, error) {
	r, err := s.vault.Open(hash)
	if err != nil {
		return false, err
	}
	defer r.Close()
	blocked, err := protocolpolicy.DisabledReader("", r)
	if err != nil {
		return false, err
	}
	_, err = io.Copy(io.Discard, r)
	return blocked, err
}

// Export rotation can hold a writer transaction when a repaired blob is first
// opened. Retire it on the serialized writer after that transaction releases.
func (s *Store) retireDisabledProtocolHash(hash string) {
	if _, busy := s.protocolRetirements.LoadOrStore(hash, true); busy {
		return
	}
	go func() {
		defer s.protocolRetirements.Delete(hash)
		tx, err := s.db.Begin()
		if err == nil {
			defer tx.Rollback()
			err = deactivateProtocolHashes(tx, []string{hash})
			if err == nil {
				err = tx.Commit()
			}
		}
		if err != nil {
			log.Print("restored disabled protocol eligibility will retry")
		}
	}()
}

func deactivateProtocolHashes(tx *sql.Tx, hashes []string) error {
	if _, err := tx.Exec("CREATE TEMP TABLE disabled_protocol_hashes(hash TEXT PRIMARY KEY) WITHOUT ROWID"); err != nil {
		return err
	}
	insert, err := tx.Prepare("INSERT INTO disabled_protocol_hashes VALUES(?)")
	if err != nil {
		return err
	}
	defer insert.Close()
	for _, h := range hashes {
		if _, err := insert.Exec(h); err != nil {
			return err
		}
	}
	_, err = tx.Exec(`
 CREATE TEMP TABLE protocol_sources AS SELECT DISTINCT source_id FROM memberships WHERE raw_hash IN disabled_protocol_hashes;
 CREATE TEMP TABLE protocol_representatives AS SELECT identity,created FROM egress_unique WHERE hash IN disabled_protocol_hashes;
 UPDATE side_jobs SET state='rejected',code='protocol_disabled',token='',lease_until=0,finished=CAST(unixepoch('subsec')*1000 AS INTEGER),
 evidence='{}',candidate_hash='',engine='',last_token=''
 WHERE state IN('accepted','pending') AND (raw_hash IN disabled_protocol_hashes OR candidate_hash IN disabled_protocol_hashes);
 DELETE FROM memberships WHERE raw_hash IN disabled_protocol_hashes;
 DELETE FROM staged WHERE hash IN disabled_protocol_hashes;
 -- An identity may have a different byte representative in another source.
 UPDATE artifacts AS a SET (hash,kind,size)=(SELECT m.raw_hash,m.kind,m.size FROM memberships m WHERE m.artifact_id=a.id ORDER BY m.raw_hash LIMIT 1)
 WHERE a.hash IN disabled_protocol_hashes AND EXISTS(SELECT 1 FROM memberships m WHERE m.artifact_id=a.id);
 DELETE FROM artifacts WHERE hash IN disabled_protocol_hashes;
 UPDATE sources SET stored_count=(SELECT count(*) FROM memberships m JOIN artifacts a ON a.id=m.artifact_id WHERE m.source_id=sources.id AND a.expires>CAST(unixepoch('subsec')*1000 AS INTEGER)),etag='',modified=''
 WHERE id IN protocol_sources;
 DELETE FROM source_admission WHERE source_id IN protocol_sources;

 -- A disallowed derived candidate alone does not invalidate a healthy input.
 -- Fence the old lease and let that input rebuild from its own immutable bytes.
 UPDATE conversion_jobs SET revision=revision+1,token='',lease_until=0,state='queued',next_run=0,version=''
 WHERE hash IN (SELECT hash FROM conversion_results WHERE candidate_hash IN disabled_protocol_hashes
 UNION SELECT hash FROM template_preparations WHERE candidate_hash IN disabled_protocol_hashes);
 DELETE FROM conversion_jobs WHERE hash IN disabled_protocol_hashes;
 DELETE FROM conversion_results WHERE candidate_hash IN disabled_protocol_hashes;
 DELETE FROM template_preparations WHERE candidate_hash IN disabled_protocol_hashes;
 DELETE FROM conversion_receipts WHERE hash IN disabled_protocol_hashes OR candidate_hash IN disabled_protocol_hashes;
 DELETE FROM repairs WHERE raw_hash IN disabled_protocol_hashes OR candidate_hash IN disabled_protocol_hashes;
 DELETE FROM export_rotation_queue WHERE candidate_hash IN disabled_protocol_hashes;
 DELETE FROM network_rotation_queue WHERE candidate_hash IN disabled_protocol_hashes;
 DELETE FROM network_classifications WHERE raw_hash IN disabled_protocol_hashes;

 UPDATE egress_jobs SET state='PENDING',reason='implementation_changed',revision=revision+1,token='',lease_until=0,claimed_at=0,
 valid_until=0,tested=0,next_run=0,candidate_hash='',candidate_size=0
 WHERE state!='DELETED' AND candidate_hash IN disabled_protocol_hashes AND hash NOT IN disabled_protocol_hashes;
 UPDATE egress_jobs SET paused=1,state='DELETED',reason='protocol_disabled',revision=revision+1,token='',claimed_at=0,lease_until=0,
 ever_accepted=0,valid_until=0,candidate_hash='',candidate_size=0,next_run=0
 WHERE state!='DELETED' AND hash IN disabled_protocol_hashes;
 DELETE FROM egress_unique WHERE hash IN disabled_protocol_hashes;
 -- Preserve a live allowed representative if an older fingerprint grouped
 -- distinct raw bytes. Its own health proof and country gates remain mandatory.
 INSERT OR IGNORE INTO egress_unique(identity,hash,created)
 SELECT p.identity,min(m.raw_hash),p.created FROM protocol_representatives p
 JOIN memberships m ON m.artifact_id=p.identity JOIN egress_jobs j ON j.hash=m.raw_hash
 WHERE j.state!='DELETED' AND NOT EXISTS(SELECT 1 FROM input_exclusions x WHERE x.identity=p.identity)
 GROUP BY p.identity;
 -- egress_metric_unique counts an insertion; swapping bytes for an existing
 -- identity must not count a new registration.
 UPDATE egress_metrics SET registered=registered-changes() WHERE id=1 AND changes()>0;
 UPDATE egress_run_members SET status='excluded',state='DELETED',completed_at=CAST(unixepoch('subsec')*1000 AS INTEGER)
 WHERE status='pending' AND hash IN disabled_protocol_hashes;
 DROP TABLE protocol_representatives;
 DROP TABLE protocol_sources;
 DROP TABLE disabled_protocol_hashes;`)
	return err
}
