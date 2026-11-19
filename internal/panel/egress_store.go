package panel

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/protocolpolicy"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
	"io"
	"time"
)

func (s *Store) ClaimEgress(ctx context.Context) (*egress.Job, error) {
	return s.ClaimEgressLane(ctx, "")
}

// Enumerate the small current/retained identity set before looking up jobs.
// Starting with the due-job index instead scans the entire historical archive on
// every idle worker poll. The authoritative views still apply all exclusions,
// Iran guards and completed-result rules to each candidate; this is not a cache.
const egressClaimCandidates = `WITH claim_scope(hash) AS MATERIALIZED (
 SELECT u.hash FROM (SELECT DISTINCT artifact_id FROM memberships) m JOIN egress_unique u ON u.identity=m.artifact_id
 UNION SELECT hash FROM egress_jobs WHERE ever_accepted=1
 UNION SELECT u.hash FROM egress_network_review v CROSS JOIN egress_unique u ON u.identity=v.identity
 UNION SELECT hash FROM egress_first_backlog
 UNION SELECT u.hash FROM egress_iran_guard g JOIN egress_unique u ON u.identity=g.identity WHERE g.state='QUARANTINED'
), dispatch(streak) AS MATERIALIZED (SELECT ` + egressDispatchStreak + `) `

const egressLiveProof = `ever_accepted=1 AND tested>0 AND valid_until>:claim_now`
const egressUrgentExpiry = egressLiveProof + ` AND valid_until<=:claim_now+120000`

const egressClaimDue = `paused=0 AND (next_run<=:claim_now OR (retry_streak=0 AND ` + egressUrgentExpiry + `)) AND (token='' OR lease_until<=:claim_now)`

// A veto follows the identity across raw representatives. Its ordinary safety
// check stays due, but the expiry of an unpublished proof is not a deadline
// for residential publication.
const egressRenewableNetwork = `NOT EXISTS(SELECT 1 FROM egress_unique u JOIN egress_network_results n ON n.identity=u.identity WHERE u.hash=egress_jobs.hash AND n.held=1) AND NOT EXISTS(SELECT 1 FROM egress_unique u JOIN egress_network_review v ON v.identity=u.identity WHERE u.hash=egress_jobs.hash)`

func egressClaimPriority(lane string, turn uint64) string {
	order := `CASE WHEN reason='ads_iran_quarantined' THEN -1
 WHEN EXISTS(SELECT 1 FROM egress_retirements r WHERE r.hash=egress_jobs.hash) THEN 0 `
	if lane == "followup" && turn%3 == 0 {
		// A zero deadline can also mean an incomplete result. Give the
		// expired-proof turn first to receipts from proven residential jobs.
		order += "WHEN ever_accepted=1 AND valid_until<=:claim_now AND " + egressRenewableNetwork + ` THEN CASE
 WHEN valid_until>0 AND tested>0 AND EXISTS(SELECT 1 FROM egress_residential_history h WHERE h.hash=egress_jobs.hash) THEN 1 ELSE 2 END `
	}
	// Keep a FIFO turn for due safety checks of withheld routes.
	if lane == "followup" && turn%4 == 0 {
		order += "WHEN tested>0 THEN 3 "
	}
	// Only already-admitted work reaches this ranking. Honor a slower probe's
	// scheduled lead on follow-up slots, including a retry whose backoff ended.
	deadline := egressUrgentExpiry
	if lane == "followup" {
		deadline = egressLiveProof + ` AND valid_until<=:claim_now+240000`
	}
	order += "WHEN " + deadline + " AND " + egressRenewableNetwork + " THEN 4 "
	if lane == "followup" {
		order += "WHEN ever_accepted=1 OR tested>0 THEN 5 "
	}
	return order + `WHEN tested=0 AND ever_accepted=1 THEN 6
 WHEN tested=0 THEN 7 WHEN ever_accepted=1 THEN 8 ELSE 9 END`
}

// Keep the materialized scope on the outer side of a join to the physical
// jobs table. A join directly to egress_work can flatten the view and scan
// the due index across every unpaused historical job before checking scope.
func egressRankedClaim(lane string, turn uint64) string {
	// On a discovery opportunity, only an individually threatened proof may
	// borrow the slot. An unrelated safety or maintenance job cannot use it.
	const discoveryOrDeadline = "CASE WHEN urgent THEN 0 WHEN queued_at IS NOT NULL THEN 1 ELSE 2 END"
	maintenanceLane := lane
	preference := "0"
	if lane == "initial" {
		preference = discoveryOrDeadline
		maintenanceLane = "followup"
	}
	return `WITH due AS MATERIALIZED (
 SELECT egress_jobs.hash,next_run,first_seen,valid_until,` + egressClaimPriority(maintenanceLane, turn) + ` AS priority,
 CASE WHEN ` + egressDiscovery + ` THEN (SELECT u.created FROM egress_unique u WHERE u.hash=c.hash) END AS queued_at,
 CASE WHEN ever_accepted=1 AND tested>0 AND valid_until>0 AND valid_until<=:claim_now+60000
 AND EXISTS(SELECT 1 FROM egress_residential_history h WHERE h.hash=c.hash)
 AND ` + egressRenewableNetwork + ` THEN 1 ELSE 0 END AS urgent
 FROM claim_scope c CROSS JOIN egress_jobs ON egress_jobs.hash=c.hash WHERE ` + egressClaimDue + `
 AND EXISTS(SELECT 1 FROM egress_work w WHERE w.hash=c.hash))
 SELECT hash FROM due CROSS JOIN dispatch ORDER BY CASE WHEN streak<=-3 THEN queued_at IS NULL
 WHEN streak=-2 THEN ` + discoveryOrDeadline + `
 WHEN streak>=2 THEN queued_at IS NOT NULL ELSE ` + preference + ` END,
 CASE WHEN queued_at IS NULL THEN priority ELSE 7 END,
 CASE WHEN priority=4 THEN valid_until END,coalesce(queued_at,next_run),
 CASE WHEN queued_at IS NULL THEN first_seen END,hash LIMIT 1`
}

// A worker's lane is a preference. Either lane can use idle capacity, and the
// durable grant streak protects both queues when only one worker obtains a permit.
func (s *Store) ClaimEgressLane(ctx context.Context, lane string) (*egress.Job, error) {
	if lane != "" && lane != "initial" && lane != "followup" {
		return nil, ErrInvalid
	}
	release, err := s.admitClaim(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	// Rank on a committed WAL snapshot, outside the writer transaction. This
	// is only a hint: claimability, scope, capacity and deadline are checked
	// again under the writer lock before granting any lease.
	now := egress.Now()
	var cleanup bool
	var candidate string
	var streak int
	ranked := egressRankedClaim(lane, s.renewalTurn.Load()+1)
	e := s.workerReader().QueryRowContext(ctx, egressClaimCandidates+`SELECT streak,
 EXISTS(SELECT 1 FROM egress_jobs WHERE token!='' AND NOT EXISTS(SELECT 1 FROM egress_inventory i WHERE i.hash=egress_jobs.hash))
 OR EXISTS(SELECT 1 FROM egress_run_members WHERE run=(SELECT max(id) FROM egress_runs) AND status='pending' AND NOT EXISTS(SELECT 1 FROM egress_inventory i WHERE i.hash=egress_run_members.hash)),
 CASE WHEN (SELECT enabled FROM egress_settings WHERE id=1)!=0 AND (SELECT count(*) FROM egress_jobs WHERE token!='' AND lease_until>:claim_now)<:worker_limit
 THEN coalesce((`+ranked+`),'') ELSE '' END FROM dispatch`, sql.Named("claim_now", now), sql.Named("worker_limit", egress.MaxWorkers)).Scan(&streak, &cleanup, &candidate)
	if e != nil || !cleanup && candidate == "" {
		return nil, e
	}
	tx, e := s.admittedTransaction(ctx, false)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "UPDATE egress_settings SET generation=generation WHERE id=1"); e != nil {
		return nil, e
	}
	now = egress.Now()
	var active, enabled int
	if cleanup {
		if _, e = tx.ExecContext(ctx, `UPDATE egress_jobs SET revision=revision+1,token='',lease_until=0 WHERE token!='' AND NOT EXISTS(SELECT 1 FROM egress_inventory i WHERE i.hash=egress_jobs.hash)`); e != nil {
			return nil, e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE egress_run_members SET status='excluded',state='OUT_OF_SCOPE',completed_at=? WHERE run=(SELECT max(id) FROM egress_runs) AND status='pending' AND NOT EXISTS(SELECT 1 FROM egress_inventory i WHERE i.hash=egress_run_members.hash)`, now); e != nil {
			return nil, e
		}
	}
	if e = tx.QueryRowContext(ctx, "SELECT enabled,(SELECT count(*) FROM egress_jobs WHERE token!='' AND lease_until>?) FROM egress_settings WHERE id=1", now).Scan(&enabled, &active); e != nil {
		return nil, e
	}
	if enabled == 0 || active >= egress.MaxWorkers || candidate == "" {
		return nil, tx.Commit()
	}
	j := &egress.Job{}
	var size int64
	var state, previousToken string
	var first, retryStreak int
	var discovery bool
	e = tx.QueryRowContext(ctx, `SELECT hash,kind,size,revision,ever_accepted,attempts,state,token,first_completed,retry_streak,`+egressDiscovery+`
 FROM egress_work WHERE hash=:job_hash AND `+egressClaimDue+` AND `+egressDispatchStreak+`=:ranked_streak`,
		sql.Named("job_hash", candidate), sql.Named("claim_now", now), sql.Named("ranked_streak", streak)).
		Scan(&j.Hash, &j.Kind, &size, &j.Revision, &j.Deep, &j.Attempt, &state, &previousToken, &first, &retryStreak, &discovery)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, tx.Commit()
	}
	if e != nil {
		return nil, e
	}
	if previousToken != "" {
		if _, e = tx.ExecContext(ctx, "UPDATE egress_metrics SET lease_recoveries=lease_recoveries+1 WHERE id=1"); e != nil {
			return nil, e
		}
	}
	// Expired leases did not produce a measurement. Recover short
	// interruptions immediately, then space subsequent attempts durably.
	if previousToken != "" && first == 0 && !j.Deep {
		retryStreak++
		if retryStreak >= 3 {
			due := now + initialRecoveryDelay(j.Hash, retryStreak-2)
			if _, err := tx.ExecContext(ctx, `UPDATE egress_jobs SET state='PENDING',reason='initial_lease_recovery',next_run=?,
 retry_streak=?,token='',lease_until=0,revision=revision+1 WHERE hash=?`, due, retryStreak, j.Hash); err != nil {
				return nil, err
			}
			return nil, tx.Commit()
		}
	}
	j.Accepted = j.Deep
	j.Deep = j.Deep || j.Attempt > 0 && state != "NO_SPLIT" && state != "UNSUPPORTED"
	j.Attempt++
	j.Token = randomToken()
	if _, e = tx.ExecContext(ctx, "UPDATE egress_jobs SET token=?,lease_until=?,claimed_at=?,attempts=attempts+1,retry_streak=? WHERE hash=?", j.Token, now+120000, now, retryStreak, j.Hash); e != nil {
		return nil, e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE egress_network_review SET attempts=attempts+1 WHERE attempts<2 AND identity=(SELECT identity FROM egress_unique WHERE hash=?)", j.Hash); e != nil {
		return nil, e
	}
	if e = recordEgressDispatch(ctx, tx.Tx, streak, discovery); e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	if !discovery {
		s.renewalTurn.Add(1)
	}
	release()
	if size > repair.MaxBytes {
		j.Issue = "input_size_limit"
		return j, nil
	}
	b, e := s.openExportBlob(j.Hash)
	if e != nil {
		j.Issue = "input_unavailable"
		return j, nil
	}
	defer b.Close()
	j.Raw, e = io.ReadAll(io.LimitReader(b, repair.MaxBytes+1))
	if e != nil || egress.Hash(j.Raw) != j.Hash {
		j.Raw = nil
		j.Issue = "input_unavailable"
	}
	return j, nil
}
func (s *Store) RenewEgress(ctx context.Context, j egress.Job) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "UPDATE egress_settings SET generation=generation WHERE id=1"); e != nil {
		return e
	}
	now := egress.Now()
	// Check this lease's identity through the authoritative view. Enumerating
	// the full historical inventory on every heartbeat monopolizes the writer.
	r, e := tx.ExecContext(ctx, "UPDATE egress_jobs SET lease_until=? WHERE hash=? AND token=? AND revision=? AND lease_until>? AND paused=0 AND state!='DELETED' AND EXISTS(SELECT 1 FROM egress_inventory i WHERE i.hash=egress_jobs.hash)", now+120000, j.Hash, j.Token, j.Revision, now)
	if e != nil {
		return e
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return ErrConflict
	}
	return tx.Commit()
}
func (s *Store) CompleteEgress(ctx context.Context, c egress.Completion) error {
	j, r := c.Job, c.Report
	if !validDigest(j.Hash) || r.Hash != j.Hash || r.Version != egress.Version || len(r.Samples) > 256 || len(r.Attempts) > 8 || len(r.Checks) > 2 || len(r.Health) > 3 || len(r.Evidence) > 4 || len(r.Delivery) > 3 {
		return ErrInvalid
	}
	for _, part := range r.Evidence {
		if len(part.Evidence) != 0 || len(part.Samples) > 256 || len(part.Checks) > 2 || len(part.Health) > 3 || len(part.Delivery) > 3 || part.Hash != j.Hash || part.Version != egress.Version {
			return ErrInvalid
		}
	}
	b, e := s.openExportBlob(j.Hash)
	var raw []byte
	if e == nil {
		raw, e = io.ReadAll(io.LimitReader(b, repair.MaxBytes+1))
		b.Close()
	}
	inputUnavailable := e != nil || egress.Hash(raw) != j.Hash
	if inputUnavailable {
		raw = nil
	}
	plan := egress.Prepare(raw)
	now := egress.Now()
	evaluate := func(now int64) (egress.Decision, string) {
		d := egress.Evaluate(r, plan, j.Hash, now)
		if inputUnavailable {
			d.State = "UNKNOWN"
			d.Reason = "input_unavailable"
			d.Eligible = false
			d.Until = 0
		}
		health := egress.AdsHealthForDecision(r, plan, d, now)
		if d.Eligible && health != "healthy" {
			d.Eligible = false
			d.State = "UNKNOWN"
			d.Reason = "payload_health_" + health
			d.Until = 0
		}
		return d, health
	}
	r.GeneralHealth = egress.Health(r, plan, now)
	d, health := evaluate(now)
	var candidateHash string
	var candidateSize int64
	if d.Eligible {
		if protocolpolicy.Disabled("", plan.Variants[1].Config) {
			return ErrInvalid
		}
		ref, e := s.vault.Put(ctx, bytes.NewReader(plan.Variants[1].Config))
		if e != nil {
			return e
		}
		defer s.vault.Release(ref.Hash)
		candidateHash, candidateSize = ref.Hash, ref.Size
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "UPDATE egress_settings SET generation=generation+1 WHERE id=1"); e != nil {
		return e
	}
	// The writer reservation is held before reading the authoritative clock.
	// Waiting for SQLite or candidate storage must not extend an expired lease.
	now = egress.Now()
	d, health = evaluate(now)
	if d.Eligible && candidateHash == "" {
		return ErrConflict
	}
	var accepted bool
	var failures, streak, firstCompleted int
	var last, claimed int64
	// Attribution belongs to the membership at completion. A safety decision
	// below can remove that membership in this same transaction.
	var firstScope string
	e = tx.QueryRowContext(ctx, `SELECT ever_accepted,failures,last_failure,claimed_at,retry_streak,first_completed,
 CASE WHEN first_completed!=0 THEN '' WHEN EXISTS (
   SELECT 1 FROM egress_unique u JOIN memberships m ON m.artifact_id=u.identity WHERE u.hash=egress_jobs.hash
 ) THEN 'current' ELSE 'withdrawn' END
 FROM egress_jobs WHERE hash=? AND revision=? AND token=? AND lease_until>? AND paused=0 AND state!='DELETED'
 AND EXISTS(SELECT 1 FROM egress_inventory i WHERE i.hash=egress_jobs.hash)`, j.Hash, j.Revision, j.Token, now).Scan(&accepted, &failures, &last, &claimed, &streak, &firstCompleted, &firstScope)
	if errors.Is(e, sql.ErrNoRows) {
		return ErrConflict
	}
	if e != nil {
		return e
	}
	if r.Started < claimed-2000 || r.Finished < r.Started || r.Finished > now+2000 {
		return ErrConflict
	}
	if firstCompleted == 0 && !accepted {
		if reason := unmeasuredFirstReason(r, d.Reason); reason != "" {
			report, err := json.Marshal(r)
			if err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, `UPDATE egress_jobs SET state='PENDING',reason=?,report=?,token='',lease_until=0,
 retry_streak=retry_streak+1,next_run=? WHERE hash=?`, reason, string(report), now+initialRecoveryDelay(j.Hash, streak+1), j.Hash); err != nil {
				return err
			}
			return tx.Commit()
		}
	}
	lifecycle, e := lifecycleState(ctx, tx)
	if e != nil {
		return e
	}
	// Reserve completion time before the ten-minute evidence deadline. Slow
	// probes are scheduled earlier, while admission remains resource bounded.
	lead := min(int64(240000), max(int64(60000), 2*(r.Finished-r.Started)+30000))
	interval := min(lifecycle.HealthMinutes*60000, egress.IranInterval-lead)
	healthUntil := int64(0)
	if health == "healthy" {
		healthUntil = now + lifecycle.HealthMinutes*60000 + 120000
	}
	if d.Eligible {
		d.Until = min(d.Until, healthUntil, r.Finished+egress.IranInterval)
	}
	if health == "unhealthy" {
		d.Reason = "ads_delivery_unhealthy"
	}
	guard, e := s.applyIran(ctx, tx, r, plan, now)
	if e != nil {
		return e
	}
	if guard.Quarantined {
		d.Eligible = false
		d.Until = 0
		d.State = "QUARANTINED"
		d.Reason = "ads_iran_quarantined"
	}
	if guard.Blocked {
		d.State = "DELETED"
		d.Reason = "confirmed_ads_iran"
	}
	state := d.State
	if accepted && !d.Eligible && !guard.Blocked {
		state = "QUARANTINED"
	}
	reason := retirementReason(d, health, accepted)
	retired, hits, err := s.retirement(ctx, tx, j.Hash, reason, d.Eligible, r.Started, r.Finished, now)
	if err != nil {
		return err
	}
	failures = hits
	if d.Eligible {
		accepted = true
		last = 0
	} else if reason != "" {
		last = now
	}
	definitive := d.Eligible || d.Negative || retired || guard.Blocked
	eventReason := d.Reason
	if retired {
		state = "DELETED"
		eventReason = reason
	}
	if health == "unhealthy" && !guard.Blocked && !retired {
		eventReason = "ads_delivery_unhealthy"
	}
	// An unsuccessful local measurement does not supersede an unexpired
	// receipt. Keep its exact bytes, timestamps and country/health evidence
	// together. Any safety finding or expired gate takes the normal path.
	proofUntil := int64(0)
	if accepted && !retired && hits == 0 && !guard.Quarantined && !inputUnavailable && inconclusiveRenewal(d, r, health) {
		err := tx.QueryRowContext(ctx, `SELECT min(e.valid_until,h.valid_until,g.valid_until)
 FROM egress_geo_eligible e JOIN egress_health h ON h.hash=e.hash JOIN egress_geo_results g ON g.hash=e.hash
 WHERE e.hash=?`, j.Hash).Scan(&proofUntil)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if proofUntil > now {
			state = "UNKNOWN" // this attempt's event, independent of the retained proof
		}
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO egress_events(hash,at,state,reason,definitive,duration_ms,first_result_scope)
 VALUES(?,?,?,?,?,?,?)`, j.Hash, now, state, eventReason, definitive, max(0, r.Finished-r.Started), firstScope); e != nil {
		return e
	}
	uniqueDefinitive := false
	if definitive {
		result, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO egress_settlements(hash,at,state) VALUES(?,?,?)", j.Hash, now, state)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		uniqueDefinitive = n == 1
	}
	if _, e = tx.ExecContext(ctx, "UPDATE egress_metrics SET completed=completed+1,first_assessments=first_assessments+?,definitive=definitive+? WHERE id=1", firstCompleted == 0, uniqueDefinitive); e != nil {
		return e
	}
	if e = recordEgressRun(ctx, tx, j.Hash, state, definitive, now, max(int64(0), r.Finished-r.Started)); e != nil {
		return e
	}
	if proofUntil > now {
		// Retry before expiration when possible without a tight claim loop.
		delay := min(egressRetryDelay(j.Hash, "UNKNOWN", "unknown", true, streak+1, interval, false), max(int64(5000), (proofUntil-now)/2))
		if _, err = tx.ExecContext(ctx, "UPDATE egress_jobs SET token='',lease_until=0,next_run=?,retry_streak=retry_streak+1 WHERE hash=?", now+delay, j.Hash); err != nil {
			return err
		}
		return tx.Commit()
	}
	if guard.Blocked {
		return tx.Commit()
	}
	if retired {
		if e = s.revokeEgress(ctx, tx, j.Hash, reason, now); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, "UPDATE egress_metrics SET unhealthy_deleted=unhealthy_deleted+1 WHERE id=1"); e != nil {
			return e
		}
		return tx.Commit()
	}
	hb, _ := json.Marshal(map[string]any{"scope": "ads_application_exchange", "status": health, "general_status": r.GeneralHealth, "general_payload": r.Health, "delivery": d.Delivery})
	if _, e = tx.ExecContext(ctx, `INSERT INTO egress_health VALUES(?,?,?,?,?) ON CONFLICT(hash) DO UPDATE SET status=excluded.status,checked_at=excluded.checked_at,valid_until=excluded.valid_until,report=excluded.report`, j.Hash, health, now, healthUntil, string(hb)); e != nil {
		return e
	}
	decision, _ := json.Marshal(d)
	report, _ := json.Marshal(r)
	// Keep proof-bearing material for an accepted member during uncertainty; every
	// output uses current eligibility, so retained data is never a stale fallback.
	if candidateHash == "" && accepted {
		if e = tx.QueryRowContext(ctx, "SELECT candidate_hash,candidate_size FROM egress_jobs WHERE hash=?", j.Hash).Scan(&candidateHash, &candidateSize); e != nil {
			return e
		}
	}
	if firstCompleted == 0 {
		// An interrupted lease is not an adverse measurement.
		streak = 0
	}
	streak++
	if d.Eligible {
		streak = 0
	}
	fastRetry := r.Code == "network_retry_pending" || j.Attempt == 1 && (d.Reason == "controls_incomplete" || d.Reason == "ads_peer_echo_incomplete" || d.Reason == "ads_profile_evidence_incomplete" || d.Reason == "ads_delivery_unproven")
	delay := egressRetryDelay(j.Hash, state, health, accepted, streak, interval, fastRetry)
	if hits > 0 {
		delay = 30000
	}
	if guard.Quarantined {
		delay = guard.Delay
	}
	if d.Eligible {
		delay = min(delay, max(int64(0), d.Until-max(lead, int64(120000))-now))
	}
	confirmNetwork, err := saveEgressNetwork(ctx, tx, r, plan, d, candidateHash, now)
	if err != nil {
		return err
	}
	reviewAgain, err := finishNetworkReview(ctx, tx, j.Hash, d)
	if err != nil {
		return err
	}
	if reviewAgain {
		delay = min(delay, int64(30000))
	}
	if confirmNetwork {
		delay = min(delay, int64(60000))
	}
	_, e = tx.ExecContext(ctx, `UPDATE egress_jobs SET state=?,reason=?,ever_accepted=?,tested=?,valid_until=?,candidate_hash=?,candidate_size=?,format=?,decision=?,report=?,token='',lease_until=0,next_run=?,failures=?,last_failure=?,retry_streak=?,first_completed=1 WHERE hash=?`, state, d.Reason, accepted, now, d.Until, candidateHash, candidateSize, plan.Format, string(decision), string(report), now+delay, failures, last, streak, j.Hash)
	if e != nil {
		return e
	}
	if e = saveEgressCountries(ctx, tx, j.Hash, r, d, now); e != nil {
		return e
	}
	if d.Eligible && !d.Network.BlocksResidential() {
		// Remember proven pre-country-filter membership for maintenance only.
		// This marker grants no route lifetime and is never used for publication.
		if _, e = tx.ExecContext(ctx, "INSERT OR IGNORE INTO egress_residential_history(hash) SELECT hash FROM egress_geo_eligible WHERE hash=?", j.Hash); e != nil {
			return e
		}
	}
	if j.Deep {
		if _, e = tx.ExecContext(ctx, "UPDATE egress_jobs SET deep_completed=1 WHERE hash=?", j.Hash); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (s *Store) revokeEgress(ctx context.Context, tx *sql.Tx, hash, reason string, now int64) error {
	for _, q := range []string{
		"INSERT INTO input_exclusions SELECT identity,?,hash,1 FROM egress_owners WHERE hash=? ON CONFLICT(identity) DO UPDATE SET at=excluded.at,hash=excluded.hash,manual=1",
	} {
		if _, e := tx.ExecContext(ctx, q, now, hash); e != nil {
			return e
		}
	}
	aliases := "SELECT o.hash FROM egress_owners o WHERE o.identity IN(SELECT identity FROM egress_owners WHERE hash=?)"
	for _, q := range []string{
		"DELETE FROM responses WHERE source_id IN(SELECT source FROM egress_owners WHERE identity IN(SELECT identity FROM egress_owners WHERE hash=?))",
		"DELETE FROM staged WHERE identity IN(SELECT identity FROM egress_owners WHERE hash=?)",
		"DELETE FROM artifacts WHERE id IN(SELECT identity FROM egress_owners WHERE hash=?)",
	} {
		if _, err := tx.ExecContext(ctx, q, hash); err != nil {
			return err
		}
	}
	for _, table := range []string{"egress_health", "egress_geo_results", "egress_countries", "conversion_results", "conversion_jobs", "egress_turns", "egress_retirements"} {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE hash=? OR hash IN("+aliases+")", hash, hash); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM repairs WHERE raw_hash=? OR raw_hash IN("+aliases+")", hash, hash); err != nil {
		return err
	}
	_, e := tx.ExecContext(ctx, "UPDATE egress_jobs SET state='DELETED',reason=CASE WHEN hash=? THEN ? ELSE 'identity_excluded' END,ever_accepted=0,revision=revision+1,token='',lease_until=0,valid_until=0,candidate_hash='',candidate_size=0,report='{}',decision='{}' WHERE hash=? OR hash IN("+aliases+")", hash, reason, hash, hash)
	return e
}
func (s *Store) manageEgress(ctx context.Context, tx *sql.Tx, action string, all bool, now int64) error {
	condition := "hash IN (SELECT hash FROM egress_owners WHERE identity IN (SELECT id FROM selected_configs))"
	if all {
		condition = "1=1"
	}
	if action == "enable" {
		if _, err := tx.ExecContext(ctx, `UPDATE egress_jobs SET state='PENDING',reason='new_input',next_run=0,retry_streak=0
 WHERE reason IN ('initial_lease_interrupted','initial_lease_exhausted') AND first_completed=0 AND tested=0 AND (`+condition+")"); err != nil {
			return err
		}
	}
	if action != "delete" {
		_, e := tx.ExecContext(ctx, "UPDATE egress_jobs SET paused=?,revision=revision+1,token='',lease_until=0,valid_until=0,next_run=0,state=CASE WHEN ever_accepted=1 THEN 'QUARANTINED' ELSE state END WHERE ("+condition+") AND state!='DELETED' AND paused!=?", action == "disable", action == "disable")
		return e
	}
	// An explicit deletion also cancels withdrawn, unassessed inputs whose
	// ordinary artifact or temporary deletion control may already have expired.
	if _, e := tx.ExecContext(ctx, "DELETE FROM egress_first_backlog WHERE "+condition); e != nil {
		return e
	}
	if _, e := tx.ExecContext(ctx, "UPDATE egress_jobs SET revision=revision+1,token='',lease_until=0,valid_until=0 WHERE ("+condition+") AND ever_accepted=0"); e != nil {
		return e
	}
	// Both exports retain identities past ordinary artifact expiry. A manual
	// deletion must also retire an archived datacenter rejection.
	rows, e := tx.QueryContext(ctx, "SELECT hash FROM egress_jobs WHERE ("+condition+`) AND state!='DELETED'
 AND (ever_accepted=1 OR hash IN (SELECT u.hash FROM egress_network_review v JOIN egress_unique u ON u.identity=v.identity) OR hash IN (SELECT u.hash FROM egress_network_results n
 JOIN egress_unique u ON u.identity=n.identity WHERE n.held=1))`)
	if e != nil {
		return e
	}
	hashes := []string{}
	for rows.Next() {
		var h string
		if e = rows.Scan(&h); e != nil {
			rows.Close()
			return e
		}
		hashes = append(hashes, h)
	}
	rows.Close()
	for _, h := range hashes {
		if e = s.revokeEgress(ctx, tx, h, "manual_delete", now); e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) expireEgress(ctx context.Context, tx *sql.Tx, now int64) error {
	// Park an interrupted final review without granting another automatic lease.
	if _, err := tx.ExecContext(ctx, `UPDATE egress_jobs SET token='',lease_until=0,revision=revision+1,
 next_run=max(next_run,?+(SELECT health_minutes*60000 FROM egress_lifecycle WHERE id=1)) WHERE token!='' AND lease_until<=? AND EXISTS(SELECT 1 FROM egress_unique u JOIN egress_network_review v ON v.identity=u.identity WHERE u.hash=egress_jobs.hash AND v.attempts=2)`, now, now); err != nil {
		return err
	}
	if _, e := tx.ExecContext(ctx, "UPDATE egress_jobs SET state='QUARANTINED',reason='evidence_expired' WHERE ever_accepted=1 AND state='RESIDENTIAL' AND valid_until<=?", now); e != nil {
		return e
	}
	// Durable investigation inputs are not ordinary output artifacts. Unknown,
	// unsupported and previously accepted inputs survive ordinary retention.

	if _, e := tx.ExecContext(ctx, "DELETE FROM egress_countries WHERE last_seen<=? OR hash IN(SELECT hash FROM egress_jobs WHERE state='DELETED')", now-egress.CountryWindow); e != nil {
		return e
	}
	if _, e := tx.ExecContext(ctx, "DELETE FROM egress_geo_results WHERE hash IN(SELECT hash FROM egress_jobs WHERE state='DELETED')"); e != nil {
		return e
	}
	_, e := tx.ExecContext(ctx, "DELETE FROM egress_events WHERE at<?", now-int64(24*time.Hour/time.Millisecond))
	return e
}
