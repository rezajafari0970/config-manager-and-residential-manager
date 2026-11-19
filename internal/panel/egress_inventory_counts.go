package panel

import "context"

type egressInventoryCounts struct {
	states                                                 map[string]int
	queue                                                  map[string]int
	total, first, assessed, retained, partial, recoverable int
	enabled                                                bool
}

// Project hash keys before joining. A work lookup otherwise expands the full
// eligibility expression once per bucket or copies archived reports into the
// temporary relation. Partial routes already have a sparse expression index.
const egressInventoryCountsSQL = `SELECT * FROM (WITH work(hash) AS MATERIALIZED (
 SELECT hash FROM egress_work
)
SELECT j.state,CASE WHEN j.paused!=0 THEN 'paused'
 WHEN j.token!='' AND j.lease_until>?1 THEN 'running'
 WHEN w.hash IS NULL THEN 'cached'
 WHEN (SELECT enabled FROM egress_settings WHERE id=1)=0 THEN 'paused'
 WHEN j.next_run<=?1 OR (j.ever_accepted=1 AND j.tested>0 AND j.retry_streak=0 AND j.valid_until>?1 AND j.valid_until<=?1+120000) THEN 'due'
 ELSE 'scheduled' END AS bucket,
 count(*),count(*) FILTER(WHERE j.tested=0),count(*) FILTER(WHERE j.tested>0),
 count(*) FILTER(WHERE j.ever_accepted=1),
 count(*) FILTER(WHERE j.hash IN(SELECT hash FROM egress_jobs INDEXED BY egress_partial WHERE json_extract(decision,'$.route')='PARTIAL_DIFFERENCE')),
 count(*) FILTER(WHERE j.paused=0 AND w.hash IS NOT NULL AND j.token!='' AND j.lease_until<=?1),
 (SELECT enabled FROM egress_settings WHERE id=1)
 FROM egress_inventory j LEFT JOIN work w ON w.hash=j.hash
 GROUP BY j.state,bucket)`

func readEgressInventoryCounts(ctx context.Context, q databaseQuery) (egressInventoryCounts, error) {
	out := egressInventoryCounts{states: map[string]int{}, queue: map[string]int{"paused": 0, "running": 0, "due": 0, "scheduled": 0, "cached": 0}}
	rows, err := q.QueryContext(ctx, egressInventoryCountsSQL, readStamp(ctx))
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var state, bucket string
		var n, first, assessed, retained, partial, recoverable int
		if err := rows.Scan(&state, &bucket, &n, &first, &assessed, &retained, &partial, &recoverable, &out.enabled); err != nil {
			return out, err
		}
		out.total += n
		out.states[state] += n
		out.queue[bucket] += n
		out.first += first
		out.assessed += assessed
		out.retained += retained
		out.partial += partial
		out.recoverable += recoverable
	}
	return out, rows.Err()
}
