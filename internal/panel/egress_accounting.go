package panel

import "context"

// Every public count and queue partition uses the same durable identity
// representative. Archive bytes and staging are storage, not pending work.
func egressAccounting(ctx context.Context, q databaseQuery) (map[string]any, error) {
	now := readStamp(ctx)
	var total, paused, running, due, scheduled, cached, first, assessed, retained int
	err := q.QueryRowContext(ctx, `SELECT count(*),
 coalesce(sum(paused!=0),0),
 coalesce(sum(paused=0 AND token!='' AND lease_until>?),0),
 coalesce(sum(paused=0 AND (token='' OR lease_until<=?) AND hash IN(SELECT hash FROM egress_work) AND (next_run<=? OR (ever_accepted=1 AND tested>0 AND valid_until>? AND valid_until<=?))),0),
 coalesce(sum(paused=0 AND (token='' OR lease_until<=?) AND hash IN(SELECT hash FROM egress_work) AND NOT (next_run<=? OR (ever_accepted=1 AND tested>0 AND valid_until>? AND valid_until<=?))),0),
 coalesce(sum(paused=0 AND (token='' OR lease_until<=?) AND hash NOT IN(SELECT hash FROM egress_work)),0),
 coalesce(sum(tested=0),0),coalesce(sum(tested>0),0),coalesce(sum(ever_accepted=1),0)
 FROM egress_inventory`, now, now, now, now, now+120000, now, now, now, now+120000, now).Scan(&total, &paused, &running, &due, &scheduled, &cached, &first, &assessed, &retained)
	if err != nil {
		return nil, err
	}
	var current, raws, missing, retainedOutside, outside, deleted int
	err = q.QueryRowContext(ctx, `SELECT
 (SELECT count(DISTINCT artifact_id) FROM memberships),
 (SELECT count(DISTINCT raw_hash) FROM memberships),
 (SELECT count(DISTINCT artifact_id) FROM memberships m WHERE NOT EXISTS(SELECT 1 FROM egress_unique u WHERE u.identity=m.artifact_id) AND NOT EXISTS(SELECT 1 FROM input_exclusions x WHERE x.identity=m.artifact_id)),
 (SELECT count(*) FROM egress_unique u JOIN egress_inventory j ON j.hash=u.hash WHERE j.ever_accepted=1 AND NOT EXISTS(SELECT 1 FROM memberships m WHERE m.artifact_id=u.identity)),
 (SELECT count(*) FROM egress_unique u JOIN egress_inventory j ON j.hash=u.hash WHERE NOT EXISTS(SELECT 1 FROM memberships m WHERE m.artifact_id=u.identity)),
 (SELECT count(*) FROM egress_unique u JOIN egress_jobs j ON j.hash=u.hash WHERE j.state='DELETED')`).Scan(&current, &raws, &missing, &retainedOutside, &outside, &deleted)
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
	var hosting, mixed int
	err = q.QueryRowContext(ctx, `SELECT
 coalesce(sum(json_extract(n.last_adverse,'$.state')='hosting'),0),
 coalesce(sum(json_extract(n.last_adverse,'$.state')='mixed'),0)
 FROM egress_eligible e JOIN egress_unique u ON u.hash=e.hash
 JOIN egress_network_results n ON n.identity=u.identity WHERE n.held=1`).Scan(&hosting, &mixed)
	if err != nil {
		return nil, err
	}
	var renewalPaused, renewalRunning, renewalDue, renewalScheduled, renewalCached int
	err = q.QueryRowContext(ctx, `SELECT
 coalesce(sum(paused!=0),0),
 coalesce(sum(paused=0 AND token!='' AND lease_until>?),0),
 coalesce(sum(paused=0 AND (token='' OR lease_until<=?) AND hash IN(SELECT hash FROM egress_work) AND (next_run<=? OR (tested>0 AND valid_until>? AND valid_until<=?))),0),
 coalesce(sum(paused=0 AND (token='' OR lease_until<=?) AND hash IN(SELECT hash FROM egress_work) AND NOT (next_run<=? OR (tested>0 AND valid_until>? AND valid_until<=?))),0),
 coalesce(sum(paused=0 AND (token='' OR lease_until<=?) AND hash NOT IN(SELECT hash FROM egress_work)),0)
 FROM egress_inventory WHERE ever_accepted=1 AND hash NOT IN(SELECT hash FROM egress_eligible)`, now, now, now, now, now+120000, now, now, now, now+120000, now).Scan(&renewalPaused, &renewalRunning, &renewalDue, &renewalScheduled, &renewalCached)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"at": now, "unit": "collector_identity", "live_versions": total, "current_identities": current, "current_versions": raws,
		"current_live_versions": total - outside, "archive_versions": outside, "deleted_versions": deleted,
		"coverage_missing": missing, "staged_coverage_missing": 0, "staged_versions": 0,
		"awaiting_first": first, "assessed_versions": assessed, "retained_outside_current": retainedOutside,
		"queue":   map[string]int{"paused": paused, "running": running, "due": due, "scheduled": scheduled, "cached": cached},
		"renewal": map[string]int{"paused": renewalPaused, "running": renewalRunning, "due": renewalDue, "scheduled": renewalScheduled, "cached": renewalCached},
		"publication": map[string]int{"retained": retained, "awaiting_proof": retained - routeEligible, "route_verified": routeEligible, "eligible": eligible,
			"hosting": hosting, "mixed": mixed, "network_unverified": routeEligible - eligible - hosting - mixed,
			"country_unknown": eligible - known, "country_filtered": known - published, "published": published, "raw_count": published, "template_count": published, "tested_template_count": published, "distinct_templates": templates, "identities": identities},
	}, nil
}
