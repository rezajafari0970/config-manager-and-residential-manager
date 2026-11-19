package panel

import (
	"database/sql"
	"encoding/json"
	"io"
	"reflect"
	"slices"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
)

// Replay only an actionable positive or a potentially affected current holding
// receipt. The job archive contains many completed negative first assessments.
const receiptRepairCandidates = `WITH candidates(hash) AS (
 SELECT hash FROM egress_jobs WHERE state='RESIDENTIAL' AND paused=0 AND valid_until>?1
 UNION SELECT j.hash FROM egress_network_results n CROSS JOIN egress_unique u ON u.identity=n.identity AND u.hash=n.hash
 CROSS JOIN egress_jobs j ON j.hash=u.hash WHERE n.held=1 AND n.checked_at=j.tested
 AND (j.kind IN ('json','custom','httpcustom','napsternet') OR j.format='sing-box'
 OR instr(j.report,'country_provider_disagreement')>0))
 SELECT c.hash FROM candidates c CROSS JOIN egress_unique u ON u.hash=c.hash
 CROSS JOIN egress_jobs j ON j.hash=c.hash WHERE j.first_completed=1 AND j.tested>0 AND j.paused=0 AND j.state!='DELETED'
 AND NOT EXISTS(SELECT 1 FROM input_exclusions x WHERE x.identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_iran_guard g WHERE g.identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM config_controls a WHERE a.id=u.identity AND a.expires>?1)
 AND NOT EXISTS(SELECT 1 FROM egress_owners o JOIN input_exclusions x ON x.identity=o.identity WHERE o.hash=c.hash)
 AND NOT EXISTS(SELECT 1 FROM egress_owners o JOIN egress_iran_guard g ON g.identity=o.identity WHERE o.hash=c.hash)
 AND NOT EXISTS(SELECT 1 FROM egress_owners o JOIN config_controls a ON a.id=o.identity WHERE o.hash=c.hash AND a.expires>?1)`

func (s *Store) repairEgressReceiptsV54(tx *sql.Tx) error {
	now := egress.Now()
	rows, err := tx.Query(receiptRepairCandidates, now)
	if err != nil {
		return err
	}
	var hashes []string
	for rows.Next() {
		var hash string
		if err = rows.Scan(&hash); err != nil {
			rows.Close()
			return err
		}
		hashes = append(hashes, hash)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, hash := range hashes {
		if err = s.repairBoundReceipt(tx, hash); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) repairBoundReceipt(tx *sql.Tx, hash string) error {
	var identity, kind, format string
	var report, decision, summary, adverse, geoSummary []byte
	var tested, finished int64
	var held bool
	err := tx.QueryRow(`SELECT u.identity,j.kind,j.format,j.report,j.decision,j.tested,
 coalesce(n.held,0),coalesce(n.last_finished,0),coalesce(n.summary,'{}'),coalesce(n.last_adverse,'{}'),coalesce(g.summary,'{}')
 FROM egress_jobs j JOIN egress_unique u ON u.hash=j.hash LEFT JOIN egress_network_results n
 ON n.identity=u.identity AND n.hash=j.hash AND n.checked_at=j.tested AND n.candidate_hash=j.candidate_hash
 LEFT JOIN egress_geo_results g ON g.hash=j.hash AND g.checked_at=j.tested AND g.complete=1
 WHERE j.hash=?`, hash).Scan(&identity, &kind, &format, &report, &decision, &tested, &held, &finished, &summary, &adverse, &geoSummary)
	if err != nil {
		return err
	}
	var r egress.Report
	var before egress.Decision
	if json.Unmarshal(report, &r) != nil || json.Unmarshal(decision, &before) != nil || !egress.ValidReportShape(r, hash) ||
		r.Started <= 0 || r.Started < tested-300000 || r.Finished < r.Started || r.Finished > tested+2000 {
		return nil
	}
	plan, available := s.receiptPlan(hash)
	if !available {
		// A mismatched selected runtime is visible even when the original
		// blob is missing. Keep any hosting hold and request fresh evidence.
		if !changedRuntime(r, format) {
			return nil
		}
		if before.Eligible {
			if err = withdrawLegacyRoute(tx, hash, tested, egress.Decision{
				State: "UNKNOWN", Route: "UNKNOWN", Reason: "variant_binding_failed", CountryConflict: before.CountryConflict,
			}); err != nil {
				return err
			}
		}
		if held {
			return requestReceiptReview(tx, identity, hash)
		}
		return nil
	}
	// Use the clock at which this exact receipt was accepted. Replaying at
	// startup time would turn all expired historical hosting data into UNKNOWN.
	d := egress.Evaluate(r, plan, hash, tested)
	badBinding := changedReceiptBinding(r, plan, kind)
	conflict := !before.CountryConflict && d.CountryConflict
	badRoute := before.Eligible && !d.Eligible && badBinding
	if before.Eligible && d.Eligible && !conflict && before.PolicyDigest == d.PolicyDigest {
		if err = repairReceiptCountries(tx, hash, r, d, tested, geoSummary); err != nil {
			return err
		}
	}
	if !conflict && !badRoute && (!held || !badBinding) {
		return nil
	}
	if conflict || badRoute {
		d.CountryConflict = d.CountryConflict || before.CountryConflict
		if err = withdrawLegacyRoute(tx, hash, tested, d); err != nil {
			return err
		}
	}
	if !held || !badBinding || d.Network.BlocksResidential() || finished != r.Finished {
		return nil
	}
	var atReceipt, previous egress.NetworkVerdict
	if json.Unmarshal(summary, &atReceipt) != nil || !atReceipt.BlocksResidential() {
		return nil // An unknown latest observation cannot disprove an older holding receipt.
	}
	originalAdverse := json.Unmarshal(adverse, &previous) == nil && reflect.DeepEqual(before.Network, atReceipt) &&
		(reflect.DeepEqual(atReceipt, previous) || reflect.DeepEqual(mergeHostingFlows(atReceipt, egress.NetworkVerdict{}), previous))
	// A merged adverse record may represent independent older proof. Keep
	// that hold. When this single receipt accounts for it all, withdraw its
	// label but preserve the adverse JSON and gate both feeds on fresh review.
	if originalAdverse {
		b, err := json.Marshal(d.Network)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`UPDATE egress_network_results SET held=0,state=?,reason=?,summary=?,valid_until=0,clean_rounds=0,clean_until=0
 WHERE identity=?`, d.Network.State, d.Network.Reason, string(b), identity); err != nil {
			return err
		}
	}
	return requestReceiptReview(tx, identity, hash)
}

func requestReceiptReview(tx *sql.Tx, identity, hash string) error {
	if _, err := tx.Exec("INSERT OR IGNORE INTO egress_network_review(identity) VALUES(?)", identity); err != nil {
		return err
	}
	_, err := tx.Exec("UPDATE egress_jobs SET next_run=0 WHERE hash=?", hash)
	return err
}

func (s *Store) receiptPlan(hash string) (egress.Plan, bool) {
	reader, err := s.vault.Open(hash)
	if err != nil {
		return egress.Plan{}, false
	}
	defer reader.Close()
	raw, err := io.ReadAll(io.LimitReader(reader, repair.MaxBytes+1))
	if err != nil || len(raw) > repair.MaxBytes || egress.Hash(raw) != hash {
		return egress.Plan{}, false
	}
	return egress.Prepare(raw), true
}

func withdrawLegacyRoute(tx *sql.Tx, hash string, tested int64, d egress.Decision) error {
	d.Eligible, d.Until = false, 0
	reason := "variant_binding_failed"
	if d.CountryConflict {
		reason = "country_iran_conflict"
	}
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE egress_jobs SET decision=?,
 state=CASE WHEN ever_accepted=1 THEN 'QUARANTINED' ELSE state END,valid_until=0,reason=?,next_run=0 WHERE hash=?`, string(b), reason, hash); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE egress_geo_results SET complete=0,status=?,valid_until=0,
 summary=json_set(summary,'$.complete',json('false'),'$.status',?,'$.valid_until',0,'$.countries',json('[]'))
 WHERE hash=? AND checked_at=?`, reason, reason, hash, tested); err != nil {
		return err
	}
	_, err = tx.Exec("DELETE FROM egress_countries WHERE hash=? AND last_seen=?", hash, tested)
	return err
}

// A replayed observation may have added a country to an otherwise valid
// profile. Remove only the contributions credited to this receipt, keeping
// the route and original deadlines when its remaining geography still holds.
func repairReceiptCountries(tx *sql.Tx, hash string, r egress.Report, d egress.Decision, tested int64, summary []byte) error {
	var old egress.CountryResult
	if json.Unmarshal(summary, &old) != nil || !old.Complete || old.ProfileKey == "" {
		return nil
	}
	current := egress.Countries(r, d, tested)
	if current.Complete && current.ProfileKey == old.ProfileKey && slices.Equal(current.Countries, old.Countries) {
		return nil
	}
	// A replay cannot add countries or transfer evidence to a different profile.
	if current.ProfileKey != old.ProfileKey || slices.ContainsFunc(current.Countries, func(c string) bool { return !slices.Contains(old.Countries, c) }) {
		current = egress.CountryResult{ProfileKey: old.ProfileKey, Status: "country_receipt_unbound"}
	}
	current.ValidUntil = min(current.ValidUntil, old.ValidUntil)
	b, err := json.Marshal(current)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE egress_geo_results SET summary=?,complete=?,status=?,valid_until=min(valid_until,?) WHERE hash=? AND checked_at=?`, string(b), current.Complete, current.Status, current.ValidUntil, hash, tested); err != nil {
		return err
	}
	for _, country := range old.Countries {
		if slices.Contains(current.Countries, country) {
			continue
		}
		if _, err = tx.Exec("DELETE FROM egress_countries WHERE hash=? AND country=? AND last_seen=?", hash, country, tested); err != nil {
			return err
		}
	}
	_, err = tx.Exec("UPDATE egress_jobs SET next_run=0 WHERE hash=?", hash)
	return err
}

func changedRuntime(r egress.Report, driver string) bool {
	if r.Core != "" && (r.Core == egress.NativeID) != (driver == "sing-box") {
		return true
	}
	if r.Core == egress.NativeID {
		for _, c := range r.Checks {
			if c.Core && c.RuntimeHash != c.Hash {
				return true
			}
		}
	}
	return false
}

func changedReceiptBinding(r egress.Report, p egress.Plan, kind string) bool {
	roundChanged := func(part egress.Report) bool {
		if changedRuntime(part, p.Driver) {
			return true
		}
		for _, c := range part.Checks {
			if !c.Core {
				continue
			}
			if c.Name == "raw" && (kind == "json" || kind == "custom" || kind == "httpcustom" || kind == "napsternet") &&
				(len(p.Variants) != 2 || c.Hash != p.Variants[0].Hash) {
				return true
			}
		}
		return false
	}
	if roundChanged(r) {
		return true
	}
	for _, part := range r.Evidence {
		if roundChanged(part) {
			return true
		}
	}
	return false
}
