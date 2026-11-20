package panel

import (
	"errors"
	"strings"
)

// Hold the right to confirm an actual Ads delivery failure under a source
// which supplied the identity. The immutable ceiling is shared by all owners
// and uses the existing exact-job grant counter, including interrupted leases.
// Three fresh reports suffice even if the original evidence window expires.
const retirementSourceSchema = `
 CREATE TABLE IF NOT EXISTS egress_retirement_limits(
 hash TEXT PRIMARY KEY REFERENCES egress_retirements(hash) ON DELETE CASCADE,
 through_attempt INTEGER NOT NULL) WITHOUT ROWID;
 CREATE TABLE IF NOT EXISTS egress_retirement_sources(
 hash TEXT NOT NULL REFERENCES egress_retirement_limits(hash) ON DELETE CASCADE,
 source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
 PRIMARY KEY(hash,source_id)) WITHOUT ROWID;
 CREATE INDEX IF NOT EXISTS egress_retirement_source ON egress_retirement_sources(source_id,hash);
 CREATE VIEW IF NOT EXISTS egress_retirement_work AS
 SELECT DISTINCT p.hash FROM egress_retirement_sources p
 CROSS JOIN sources s ON s.id=p.source_id CROSS JOIN egress_jobs j ON j.hash=p.hash
 CROSS JOIN egress_unique u ON u.hash=p.hash CROSS JOIN egress_retirement_limits l ON l.hash=p.hash
 WHERE s.enabled=1 AND j.first_completed=1 AND j.ever_accepted=0 AND j.paused=0 AND j.state!='DELETED'
 AND (j.attempts<l.through_attempt OR (j.token!='' AND j.attempts=l.through_attempt AND j.lease_until>CAST(unixepoch('subsec')*1000 AS INTEGER)))
 AND NOT EXISTS(SELECT 1 FROM config_controls c WHERE c.id=u.identity AND c.expires>CAST(unixepoch('subsec')*1000 AS INTEGER))
 AND NOT EXISTS(SELECT 1 FROM input_exclusions x WHERE x.identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_iran_guard g WHERE g.identity=u.identity);
 CREATE TRIGGER IF NOT EXISTS egress_retirement_source_alias AFTER INSERT ON memberships BEGIN
 INSERT OR IGNORE INTO egress_retirement_sources(hash,source_id)
 SELECT u.hash,NEW.source_id FROM egress_unique u JOIN egress_retirement_limits l ON l.hash=u.hash JOIN egress_jobs j ON j.hash=u.hash
 WHERE u.identity=NEW.artifact_id AND j.attempts<l.through_attempt;
 END;
 CREATE TRIGGER IF NOT EXISTS egress_retirement_spent AFTER UPDATE OF state,token ON egress_jobs
 WHEN NEW.state='DELETED' OR (OLD.token!='' AND NEW.token='') BEGIN
 DELETE FROM egress_retirement_limits WHERE hash=NEW.hash AND (NEW.state='DELETED' OR through_attempt<=NEW.attempts);
 END;
 CREATE TRIGGER IF NOT EXISTS egress_retirement_source_replaced AFTER UPDATE OF url_hash ON sources WHEN NEW.url_hash!=OLD.url_hash BEGIN
 DELETE FROM egress_retirement_sources WHERE source_id=OLD.id; END;`

// Disabling or removing the last eligible source fences a previously issued
// supplemental lease, even if the source or the same input is added again
// before that worker returns. Independent network and Iran work retains its
// own custody; a remaining second source also keeps this exact lease valid.
func supplementalSourceFences(prefix, sourceTable string) string {
	fence := `
 UPDATE egress_jobs SET token='',lease_until=0,revision=revision+1
 WHERE ever_accepted=0 AND first_completed=1 AND token!='' AND hash IN(
 SELECT p.hash FROM ` + sourceTable + ` p JOIN egress_unique u ON u.hash=p.hash
 WHERE p.source_id=OLD.id AND NOT EXISTS(SELECT 1 FROM ` + sourceTable + ` other JOIN sources s ON s.id=other.source_id
 WHERE other.hash=p.hash AND other.source_id!=OLD.id AND s.enabled=1)
 AND NOT EXISTS(SELECT 1 FROM egress_iran_guard g WHERE g.identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_network_review v WHERE v.identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_network_results n WHERE n.identity=u.identity AND n.held=1 AND n.clean_rounds=1));`

	return `
 CREATE TRIGGER IF NOT EXISTS ` + prefix + `_fence_source BEFORE UPDATE OF url_hash,enabled ON sources
 WHEN NEW.url_hash!=OLD.url_hash OR (OLD.enabled=1 AND NEW.enabled=0) BEGIN ` + fence + ` END;
 CREATE TRIGGER IF NOT EXISTS ` + prefix + `_fence_deleted BEFORE DELETE ON sources BEGIN ` + fence + ` END;`
}

func (s *Store) migrateV54() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version >= 54 {
		return err
	}
	if _, err = tx.Exec(retirementSourceSchema + supplementalSourceFences("egress_retirement", "egress_retirement_sources")); err != nil {
		return err
	}
	// Reconstruct ownership only from an accepted membership or an exact,
	// still-authorized natural withdrawal, never from a staged historical
	// sighting. An exhausted old confirmation stays closed.
	_, err = tx.Exec(`DELETE FROM egress_retirements AS r WHERE r.reason='confirmed_ads_delivery_unhealthy' AND EXISTS(
 SELECT 1 FROM egress_jobs j JOIN egress_owners o ON o.hash=j.hash JOIN egress_iran_guard g ON g.identity=o.identity
 JOIN input_exclusions x ON x.identity=o.identity WHERE j.hash=r.hash AND j.state='DELETED' AND g.state='BLOCKED');
 INSERT OR IGNORE INTO egress_retirement_limits(hash,through_attempt)
 SELECT r.hash,j.attempts+3 FROM egress_retirements r JOIN egress_jobs j ON j.hash=r.hash JOIN egress_unique u ON u.hash=j.hash
 WHERE r.reason='confirmed_ads_delivery_unhealthy' AND j.first_completed=1 AND j.tested>0 AND j.ever_accepted=0
 AND j.state!='DELETED' AND j.paused=0 AND j.retry_streak BETWEEN 1 AND 2
 AND NOT EXISTS(SELECT 1 FROM egress_iran_guard g WHERE g.identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM input_exclusions x WHERE x.identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM config_controls c WHERE c.id=u.identity AND c.expires>CAST(unixepoch('subsec')*1000 AS INTEGER));
 WITH owners(source_id,hash) AS (
 SELECT m.source_id,u.hash FROM memberships m JOIN egress_unique u ON u.identity=m.artifact_id
 UNION SELECT b.source_id,u.hash FROM conversion_first_backlog b JOIN egress_unique u ON u.identity=b.identity
 WHERE b.hash=u.hash OR EXISTS(SELECT 1 FROM egress_owners o WHERE o.hash=b.hash AND o.identity=b.identity AND o.source=b.source_id)
 ) INSERT OR IGNORE INTO egress_retirement_sources(hash,source_id)
 SELECT l.hash,p.source_id FROM owners p JOIN sources s ON s.id=p.source_id AND s.enabled=1
 JOIN egress_retirement_limits l ON l.hash=p.hash`)
	if err != nil {
		return err
	}
	if err = s.recoverCompatibleReceipts(tx); err != nil {
		return err
	}
	// Keep the existing eligibility and network safety views. Change only
	// worker custody for a bounded, sourced confirmation.
	for _, v := range []struct{ name, old, replacement string }{
		{"egress_inventory", "OR j.ever_accepted=1", "OR j.ever_accepted=1 OR EXISTS(SELECT 1 FROM egress_retirement_work p WHERE p.hash=j.hash) OR EXISTS(SELECT 1 FROM egress_compatibility_work p WHERE p.hash=j.hash)"},
		{"egress_work", "OR (g.identity IS NULL AND j.retry_streak<3 AND EXISTS(SELECT 1 FROM egress_retirements", "OR (g.identity IS NULL AND EXISTS(SELECT 1 FROM egress_compatibility_work p WHERE p.hash=j.hash)) OR (g.identity IS NULL AND EXISTS(SELECT 1 FROM egress_retirement_work p WHERE p.hash=j.hash)) OR (g.identity IS NULL AND j.ever_accepted=1 AND j.retry_streak<3 AND EXISTS(SELECT 1 FROM egress_retirements"},
	} {
		var definition string
		if err = tx.QueryRow("SELECT sql FROM sqlite_schema WHERE name=?", v.name).Scan(&definition); err != nil {
			return err
		}
		if strings.Contains(definition, "egress_retirement_work") || strings.Contains(definition, "egress_first_arrivals") || strings.Contains(definition, "j.ever_accepted=1 AND g.identity IS NULL") {
			continue
		}
		if strings.Count(definition, v.old) != 1 {
			return errors.New("unrecognized Residential retirement view")
		}
		if _, err = tx.Exec("DROP VIEW " + v.name + ";" + strings.Replace(definition, v.old, v.replacement, 1)); err != nil {
			return err
		}
	}
	if err = migrateResponseInputs(tx); err != nil {
		return err
	}
	if err = s.repairEgressReceiptsV54(tx); err != nil {
		return err
	}
	if _, err = tx.Exec("PRAGMA user_version=54"); err != nil {
		return err
	}
	return tx.Commit()
}
