package panel

import "context"

type firstQueueScope struct {
	Awaiting         int   `json:"awaiting"`
	Ready            int   `json:"ready"`
	Running          int   `json:"running"`
	Delayed          int   `json:"delayed"`
	DelayedRecovery  int   `json:"delayed_recovery"`
	Paused           int   `json:"paused"`
	SafetyReview     int   `json:"safety_review"`
	Excluded         int   `json:"excluded"`
	OperatorExcluded int   `json:"operator_excluded"`
	Missing          int   `json:"missing_job"`
	OldestReadyAt    int64 `json:"oldest_ready_at"`
	OldestReadyAge   int64 `json:"oldest_ready_age_ms"`
	OldestWaitingAt  int64 `json:"oldest_waiting_at"`
	OldestWaitingAge int64 `json:"oldest_waiting_age_ms"`
}

type firstResultsWindow struct {
	Historical   int      `json:"historical"` // Subset of Withdrawn completed on an archive lease.
	PerMinute    *float64 `json:"per_minute"`
	ObservedFrom int64    `json:"observed_from"`
	ObservedMS   int64    `json:"observed_ms"`
	Current      int      `json:"current"`
	Withdrawn    int      `json:"withdrawn"`
}

type firstAssessmentProgress struct {
	Current        firstQueueScope    `json:"current"`
	Withdrawn      firstQueueScope    `json:"withdrawn"`
	FirstResults5m firstResultsWindow `json:"first_results_5m"`
}

// These counters describe the selected historical recovery cohort. The
// operational phase tracks admission; only a completed first receipt moves
// the identity to completed, including after a handoff to the normal queue.
type archiveRecoveryProgress struct {
	Total       int `json:"total"`
	Waiting     int `json:"waiting"`
	Active      int `json:"active"`
	Promoted    int `json:"promoted"`
	Completed   int `json:"completed"`
	Unavailable int `json:"unavailable"`
	Paused      int `json:"paused"`
	Cancelled   int `json:"cancelled"`
}

func archiveRecoveryState(ctx context.Context, q databaseQuery) (archiveRecoveryProgress, error) {
	var a archiveRecoveryProgress
	// The ledger updates these seven counters in the same transaction as the
	// phase transition. The dashboard never enumerates historical identities.
	err := q.QueryRowContext(ctx, `SELECT coalesce(sum(total),0),
 coalesce(max(total) FILTER (WHERE phase='waiting'),0),
 coalesce(max(total) FILTER (WHERE phase='active'),0),
 coalesce(max(total) FILTER (WHERE phase='promoted'),0),
 coalesce(max(total) FILTER (WHERE phase='completed'),0),
 coalesce(max(total) FILTER (WHERE phase='unavailable'),0),
 coalesce(max(total) FILTER (WHERE phase='paused'),0),
 coalesce(max(total) FILTER (WHERE phase='cancelled'),0)
 FROM egress_first_history_counts`).Scan(&a.Total, &a.Waiting, &a.Active, &a.Promoted, &a.Completed, &a.Unavailable, &a.Paused, &a.Cancelled)
	return a, err
}

// Limit the driving keys to committed memberships and explicitly preserved
// withdrawals. One current membership takes precedence over any withdrawal.
const firstAssessmentQueueSQL = `SELECT * FROM (WITH population AS MATERIALIZED (
 SELECT identity,max(present) AS present FROM (
   SELECT DISTINCT artifact_id AS identity,1 AS present FROM memberships
   UNION ALL SELECT u.identity,0 FROM (SELECT DISTINCT hash FROM egress_first_backlog) b
   CROSS JOIN egress_unique u ON u.hash=b.hash
 ) GROUP BY identity
), states AS (
 SELECT k.present,u.created,j.retry_streak,(c.action='deleted' OR j.reason='manual_delete') AS operator_excluded,CASE
   WHEN x.identity IS NOT NULL OR g.state='BLOCKED' OR c.action='deleted' OR j.state='DELETED' THEN 'excluded'
   WHEN j.hash IS NULL THEN 'missing'
   WHEN j.paused!=0 THEN 'paused'
   WHEN j.reason='ads_iran_quarantined' THEN 'safety'
   WHEN j.token!='' AND j.lease_until>?1 THEN 'running'
   WHEN (SELECT enabled FROM egress_settings WHERE id=1)=0 THEN 'paused'
   WHEN j.next_run>?1 THEN 'delayed'
   ELSE 'ready' END AS bucket
 FROM population k ` + currentEgressJoins + ` AND c.expires>?1
 WHERE j.hash IS NULL OR (j.first_completed=0 AND j.tested=0)
)
SELECT present,
 count(*) FILTER(WHERE bucket='ready'),count(*) FILTER(WHERE bucket='running'),
 count(*) FILTER(WHERE bucket='delayed'),count(*) FILTER(WHERE bucket='paused'),
 count(*) FILTER(WHERE bucket='excluded'),count(*) FILTER(WHERE bucket='missing'),
 count(*) FILTER(WHERE bucket='safety'),count(*) FILTER(WHERE bucket='excluded' AND operator_excluded),
 count(*) FILTER(WHERE bucket='delayed' AND retry_streak>0),
 coalesce(min(created) FILTER(WHERE bucket='ready' AND created>0),0),
 coalesce(min(created) FILTER(WHERE bucket IN ('ready','delayed') AND created>0),0)
 FROM states GROUP BY present)`

func firstAssessmentState(ctx context.Context, q databaseQuery, now int64) (firstAssessmentProgress, error) {
	var progress firstAssessmentProgress
	rows, err := q.QueryContext(ctx, firstAssessmentQueueSQL, now)
	if err != nil {
		return progress, err
	}
	for rows.Next() {
		var present bool
		var scope firstQueueScope
		err = rows.Scan(&present, &scope.Ready, &scope.Running, &scope.Delayed, &scope.Paused, &scope.Excluded, &scope.Missing, &scope.SafetyReview, &scope.OperatorExcluded, &scope.DelayedRecovery, &scope.OldestReadyAt, &scope.OldestWaitingAt)
		if err != nil {
			rows.Close()
			return progress, err
		}
		scope.Awaiting = scope.Ready + scope.Delayed + scope.Running + scope.Paused + scope.SafetyReview
		if scope.OldestReadyAt > 0 {
			scope.OldestReadyAge = max(0, now-scope.OldestReadyAt)
		}
		if scope.OldestWaitingAt > 0 {
			scope.OldestWaitingAge = max(0, now-scope.OldestWaitingAt)
		}
		if present {
			progress.Current = scope
		} else {
			progress.Withdrawn = scope
		}
	}
	if err = rows.Close(); err != nil {
		return progress, err
	}
	if err = rows.Err(); err != nil {
		return progress, err
	}
	window := &progress.FirstResults5m
	// Earlier installations did not distinguish first results from repeat
	// checks. Never extrapolate a partial observation window across an upgrade.
	err = q.QueryRowContext(ctx, `SELECT max(?-300000,CAST(value AS INTEGER)) FROM metadata WHERE key='egress-first-results-since'`, now).Scan(&window.ObservedFrom)
	if err != nil {
		return progress, err
	}
	window.ObservedMS = max(0, now-window.ObservedFrom)
	err = q.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE first_result_scope='current'),
 count(*) FILTER(WHERE first_result_scope IN('withdrawn','historical')),
 count(*) FILTER(WHERE first_result_scope='historical') FROM egress_events WHERE at>=? AND at>? AND at<=?`, window.ObservedFrom, now-300000, now).Scan(&window.Current, &window.Withdrawn, &window.Historical)
	if err == nil && window.ObservedMS == 300000 {
		rate := float64(window.Current+window.Withdrawn) / 5
		window.PerMinute = &rate
	}
	return progress, err
}
