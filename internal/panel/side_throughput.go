package panel

import (
	"context"
	"strings"
	"time"
)

// A rolling window counts each identity's committed decision once. Retries,
// expired-before-test rows, and infrastructure outages cannot inflate the rate.
type sideThroughput struct {
	Decided int `json:"decided_15m"`
	Full    int `json:"all_checks_15m"`
	Target  int `json:"target_15m"`
}

// Generate the filters from the same fixed keys and outcomes used in the
// reviews. The recent index bounds the JSON work to this time window.
var sideThroughputQuery = `SELECT count(*),count(*) FILTER (WHERE
 (SELECT count(*) FROM json_each(j.evidence) AS e WHERE
  (CASE WHEN j.evidence->>'$.raw_checks'='failed' THEN
    CASE WHEN substr(e.key,1,4)='raw_' THEN substr(e.key,5) END
   ELSE e.key END) IN ('` + strings.Join(sideServices[:], "','") + `')
  AND e.value IN ('` + strings.Join(sideMeasuredOutcomes, "','") + `')) = ?)
 FROM side_jobs AS j INDEXED BY side_recent WHERE j.finished>0 AND j.finished>? AND j.finished<=?
 AND j.state IN ('accepted','rejected')`

func readSideThroughput(ctx context.Context, q readQuerier) (sideThroughput, error) {
	v := sideThroughput{Target: 2000}
	now := readStamp(ctx)
	err := q.QueryRowContext(ctx, sideThroughputQuery, len(sideServices), now-(15*time.Minute).Milliseconds(), now).
		Scan(&v.Decided, &v.Full)
	return v, err
}
