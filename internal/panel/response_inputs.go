package panel

import (
	"context"
	"database/sql"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/collect"
)

// A cached response and the last admitted generation can contain different
// identities. Keep provenance for exactly the parsed bytes held by responses.
func migrateResponseInputs(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS response_inputs(
 source_id TEXT NOT NULL REFERENCES responses(source_id) ON DELETE CASCADE,
 identity TEXT NOT NULL,PRIMARY KEY(source_id,identity)) WITHOUT ROWID;
 CREATE INDEX IF NOT EXISTS response_input_identity ON response_inputs(identity,source_id);
 CREATE TRIGGER IF NOT EXISTS response_inputs_replaced AFTER UPDATE OF hash ON responses WHEN old.hash!=new.hash BEGIN
 DELETE FROM response_inputs WHERE source_id=new.source_id;
 END;
 DELETE FROM responses WHERE source_id IN(
 SELECT a.source_id FROM source_admission a JOIN responses r ON r.source_id=a.source_id AND r.hash=a.raw_hash
 WHERE a.decision='drop_retry' AND NOT EXISTS(SELECT 1 FROM response_inputs i WHERE i.source_id=a.source_id)
 AND EXISTS(SELECT 1 FROM egress_iran_guard g JOIN egress_owners o ON o.identity=g.identity WHERE o.source=a.source_id));`)
	return err
}

func recordResponseInputs(ctx context.Context, tx *sql.Tx, source string, result collect.Result, token string) error {
	if result.Raw.Hash == "" {
		return nil
	}
	var needed bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM responses r WHERE r.source_id=? AND r.hash=?
 AND NOT EXISTS(SELECT 1 FROM response_inputs i WHERE i.source_id=r.source_id))`, source, result.Raw.Hash).Scan(&needed); err != nil || !needed {
		return err
	}
	inputs, arg, err := sourceInputQuery(result, token)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO response_inputs(source_id,identity) SELECT ?,identity FROM ("+inputs+")", source, arg)
	return err
}

// Scope cache invalidation to the received identities. An older or unparsed
// cache has no body index, so consult its recorded source ownership instead.
const revokeResponseInputsSQL = `WITH affected(identity) AS (SELECT identity FROM egress_owners WHERE hash=?)
 DELETE FROM responses WHERE source_id IN (
 SELECT i.source_id FROM affected a JOIN response_inputs i ON i.identity=a.identity
 UNION
 SELECT o.source FROM affected a JOIN egress_owners o ON o.identity=a.identity
 WHERE NOT EXISTS(SELECT 1 FROM response_inputs i WHERE i.source_id=o.source))`
