package panel

import "context"

// Every public count and queue partition uses the same durable identity
// representative. Archive bytes and staging are storage, not pending work.
func egressAccounting(ctx context.Context, q databaseQuery) (map[string]any, error) {
	inventory, err := readEgressInventoryCounts(ctx, q)
	if err != nil {
		return nil, err
	}
	return inventory.accounting(ctx, q)
}

func (inventory egressInventoryCounts) accounting(ctx context.Context, q databaseQuery) (map[string]any, error) {
	now := readStamp(ctx)
	// Count committed identities once, using the same states as the source table.
	// An identity retained after withdrawal belongs only in the maintenance totals.
	var current, currentTested, currentAwaiting, currentExcluded, interrupted, exhausted, missing int
	err := q.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER(WHERE bucket='tested'),
 count(*) FILTER(WHERE bucket='awaiting'),count(*) FILTER(WHERE bucket='excluded'),count(*) FILTER(WHERE bucket='missing'),
 count(*) FILTER(WHERE bucket='awaiting' AND reason IN ('initial_lease_interrupted','initial_lease_recovery')),
 count(*) FILTER(WHERE bucket='awaiting' AND reason='initial_lease_exhausted')
 FROM (SELECT `+currentEgressBucket+` AS bucket,j.reason FROM (SELECT DISTINCT artifact_id AS identity FROM memberships) k `+currentEgressJoins+` AND c.expires>?)`, now).Scan(&current, &currentTested, &currentAwaiting, &currentExcluded, &missing, &interrupted, &exhausted)
	if err != nil {
		return nil, err
	}
	var raws, retainedOutside, outside, deleted, staged, stagedMissing int
	err = q.QueryRowContext(ctx, `SELECT
 (SELECT count(DISTINCT raw_hash) FROM memberships),
 (SELECT count(*) FROM egress_unique u JOIN egress_inventory j ON j.hash=u.hash WHERE j.ever_accepted=1 AND NOT EXISTS(SELECT 1 FROM memberships m WHERE m.artifact_id=u.identity)),
 (SELECT count(*) FROM egress_unique u JOIN egress_inventory j ON j.hash=u.hash WHERE NOT EXISTS(SELECT 1 FROM memberships m WHERE m.artifact_id=u.identity)),
 (SELECT count(*) FROM egress_unique u JOIN egress_jobs j ON j.hash=u.hash WHERE j.state='DELETED'),
 (SELECT count(DISTINCT t.hash) FROM sources s JOIN staged t ON t.token=s.lease_token AND t.source_id=s.id
   WHERE s.enabled=1 AND s.lease_until>?),
 (SELECT count(DISTINCT t.hash) FROM sources s JOIN staged t ON t.token=s.lease_token AND t.source_id=s.id
   WHERE s.enabled=1 AND s.lease_until>? AND NOT EXISTS(SELECT 1 FROM egress_jobs j WHERE j.hash=t.hash)
   AND NOT EXISTS(SELECT 1 FROM input_exclusions x WHERE x.identity=t.identity))`, now, now).Scan(&raws, &retainedOutside, &outside, &deleted, &staged, &stagedMissing)
	if err != nil {
		return nil, err
	}
	var routeEligible, eligible, known, published, templates, identities int
	err = q.QueryRowContext(ctx, `SELECT
 (SELECT count(*) FROM egress_eligible),(SELECT count(*) FROM egress_network_eligible),(SELECT count(*) FROM egress_geo_eligible),
 (SELECT count(*) FROM egress_export_eligible),(SELECT count(DISTINCT candidate_hash) FROM egress_export_eligible),
 (SELECT count(*) FROM egress_unique u JOIN egress_export_eligible e ON e.hash=u.hash)`).Scan(&routeEligible, &eligible, &known, &published, &templates, &identities)
	if err != nil {
		return nil, err
	}
	// Count holds by the last credible adverse observation. A later incomplete
	// receipt does not release a hold. Scope the partition to current split proofs.
	var hosting, mixed, access, shared int
	err = q.QueryRowContext(ctx, `SELECT
 coalesce(sum(n.held=1 AND json_extract(n.last_adverse,'$.state')='hosting'),0),
 coalesce(sum(n.held=1 AND json_extract(n.last_adverse,'$.state')='mixed'),0),
 coalesce(sum(v.identity IS NULL AND n.held=0 AND n.state='access' AND n.hash=e.hash AND n.candidate_hash=e.candidate_hash AND n.checked_at=e.tested AND n.valid_until>?),0),
 coalesce(sum(v.identity IS NULL AND n.held=0 AND n.hash=e.hash AND n.candidate_hash=e.candidate_hash AND n.checked_at=e.tested AND json_array_length(n.summary,'$.shared_hosting')>0),0)
 FROM egress_eligible e JOIN egress_unique u ON u.hash=e.hash
 LEFT JOIN egress_network_results n ON n.identity=u.identity
 LEFT JOIN egress_network_review v ON v.identity=u.identity`, now).Scan(&hosting, &mixed, &access, &shared)
	if err != nil {
		return nil, err
	}
	renewal, safety, err := egressRenewalCounts(ctx, q, now)
	if err != nil {
		return nil, err
	}
	// A global pause stops new grants. Already leased and cached identities
	// keep their state until the worker returns or the lease expires.
	if !inventory.enabled {
		renewal["paused"] += renewal["due"] + renewal["scheduled"]
		renewal["due"], renewal["scheduled"] = 0, 0
	}
	firstProgress, err := firstAssessmentState(ctx, q, now)
	if err != nil {
		return nil, err
	}
	archive, err := archiveRecoveryState(ctx, q)
	if err != nil {
		return nil, err
	}
	awaiting := renewal["paused"] + renewal["running"] + renewal["due"] + renewal["scheduled"] + renewal["cached"]
	return map[string]any{
		"at": now, "unit": "collector_identity", "live_versions": inventory.total, "current_identities": current, "current_versions": raws,
		"current_live_versions": inventory.total - outside, "archive_versions": outside, "deleted_versions": deleted,
		"coverage_missing": missing, "staged_coverage_missing": stagedMissing, "staged_versions": staged,
		"archive_recovery":   archive,
		"first_assessment":   firstProgress,
		"current_assessment": map[string]int{"tested": currentTested, "awaiting": currentAwaiting, "excluded": currentExcluded, "missing": missing, "interrupted": interrupted, "exhausted": exhausted},
		"awaiting_first":     inventory.first, "assessed_versions": inventory.assessed, "retained_outside_current": retainedOutside,
		"queue":   inventory.queue,
		"renewal": renewal, "safety_review": safety,
		"publication": map[string]int{"retained": inventory.retained, "awaiting_proof": awaiting, "route_verified": routeEligible, "eligible": eligible,
			"hosting": hosting, "mixed": mixed, "network_unverified": routeEligible - eligible - hosting - mixed, "eligible_network_unattributed": eligible - access, "eligible_with_shared_hosting": shared,
			"country_unknown": eligible - known, "country_filtered": known - published, "published": published, "raw_count": published, "template_count": published, "tested_template_count": published, "distinct_templates": templates, "identities": identities},
	}, nil
}

// Partition retained identities without current route proof. A durable veto
// still applies after route expiry. Its next safety check is not a renewal
// prospect, even when it has a live worker lease.
func egressRenewalCounts(ctx context.Context, q databaseQuery, now int64) (map[string]int, map[string]int, error) {
	renewal := map[string]int{"paused": 0, "running": 0, "due": 0, "scheduled": 0, "cached": 0}
	safety := map[string]int{"iran": 0, "country_conflict": 0, "network": 0, "route_or_health_loss": 0, "network_review": 0}
	rows, err := q.QueryContext(ctx, `SELECT bucket,count(*) FROM (
 SELECT CASE
   WHEN g.state='QUARANTINED' THEN 'iran'
   WHEN j.hash IN (SELECT hash FROM egress_jobs WHERE json_extract(decision,'$.country_conflict')=1) THEN 'country_conflict'
   WHEN n.held=1 THEN 'network'
   WHEN v.identity IS NOT NULL THEN 'network_review'
   WHEN r.hash IS NOT NULL THEN 'route_or_health_loss'
   WHEN j.paused!=0 THEN 'paused'
   WHEN j.token!='' AND j.lease_until>? THEN 'running'
   WHEN j.hash NOT IN (SELECT hash FROM egress_work) THEN 'cached'
   WHEN j.next_run<=? OR (j.tested>0 AND j.retry_streak=0 AND j.valid_until>? AND j.valid_until<=?) THEN 'due'
   ELSE 'scheduled' END AS bucket
 FROM egress_inventory j JOIN egress_unique u ON u.hash=j.hash
 LEFT JOIN egress_iran_guard g ON g.identity=u.identity
 LEFT JOIN egress_network_results n ON n.identity=u.identity
 LEFT JOIN egress_retirements r ON r.hash=j.hash
 LEFT JOIN egress_network_review v ON v.identity=u.identity
 WHERE j.ever_accepted=1 AND j.hash NOT IN(SELECT hash FROM egress_eligible)
 ) GROUP BY bucket`, now, now, now, now+120000)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var bucket string
		var count int
		if err := rows.Scan(&bucket, &count); err != nil {
			return nil, nil, err
		}
		if _, isSafetyReview := safety[bucket]; isSafetyReview {
			safety[bucket] = count
		} else {
			renewal[bucket] = count
		}
	}
	return renewal, safety, rows.Err()
}
