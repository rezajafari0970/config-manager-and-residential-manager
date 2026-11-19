package panel

import (
	"database/sql"
	"encoding/json"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/convert"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/native"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/probe"
)

// Retained positive receipts can outlive an ordinary job and its result. Record
// the witnessed first measurement, including an expired one, without altering
// eligibility, health clocks, or the normal retest schedule.
func rememberMeasuredOrdinaryReceipts(tx *sql.Tx) error {
	rows, err := tx.Query(`SELECT hash,candidate_hash,engine,rule,tested,valid_until,metadata
 FROM conversion_receipts WHERE version=? AND candidate_hash=runtime_hash AND candidate_size>0
 AND core='passed' AND connection='passed' AND code='https_payload_verified'
 AND tested>0 AND valid_until>tested AND tested<=CAST(unixepoch('subsec')*1000 AS INTEGER)
 ORDER BY tested,hash`, convert.Version)
	if err != nil {
		return err
	}
	type measured struct {
		hash   string
		tested int64
	}
	var receipts []measured
	for rows.Next() {
		var hash, candidate, engine, rule string
		var tested, until int64
		var encoded []byte
		if err = rows.Scan(&hash, &candidate, &engine, &rule, &tested, &until, &encoded); err != nil {
			rows.Close()
			return err
		}
		var evidence struct {
			Raw                          string `json:"raw_sha256"`
			Candidate                    string `json:"candidate_sha256"`
			Runtime                      string `json:"runtime_sha256"`
			Core                         string `json:"core_sha256"`
			ReusedFrom                   string `json:"reused_from_raw_sha256"`
			Engine, Rule, Pipeline, Code string
			Tested                       int64
			Checks                       map[string]string
		}
		if !validDigest(hash) || !validDigest(candidate) || json.Unmarshal(encoded, &evidence) != nil ||
			evidence.Raw != hash || evidence.ReusedFrom != "" || evidence.Candidate != candidate || evidence.Runtime != candidate ||
			evidence.Engine != engine || evidence.Pipeline != convert.Version || evidence.Rule != rule || evidence.Code != "https_payload_verified" ||
			evidence.Tested < tested || evidence.Tested >= until || !probe.VerifiedPayload(evidence.Checks) {
			continue
		}
		switch engine {
		case "xray":
			if evidence.Core != probe.CoreSHA256 || !probe.VerifiedEvidence(evidence.Checks) {
				continue
			}
		case "sing-box":
			if evidence.Core != native.NativeSHA || !probe.VerifiedNativeEvidence(evidence.Checks) {
				continue
			}
		default:
			continue
		}
		receipts = append(receipts, measured{hash, tested})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	record, err := tx.Prepare(`INSERT INTO conversion_first_assessed(identity,hash,version,tested)
 SELECT min(o.identity),o.hash,?,? FROM egress_owners o WHERE o.hash=? GROUP BY o.hash HAVING count(DISTINCT o.identity)=1
 ON CONFLICT(identity) DO UPDATE SET hash=excluded.hash,version=excluded.version,tested=excluded.tested
 WHERE excluded.tested<conversion_first_assessed.tested`)
	if err != nil {
		return err
	}
	defer record.Close()
	for _, r := range receipts {
		if _, err = record.Exec(convert.Version, r.tested, r.hash); err != nil {
			return err
		}
	}
	_, err = tx.Exec(`DELETE FROM conversion_first_backlog WHERE EXISTS(SELECT 1 FROM conversion_first_assessed a WHERE a.identity=conversion_first_backlog.identity)`)
	return err
}
