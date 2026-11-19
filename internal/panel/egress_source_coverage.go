package panel

import (
	"context"
	"net/http"
	"strconv"
	"time"
	"unicode"
	"unicode/utf8"
)

const egressSourcePageSize = 50

type egressCoverageCounts struct {
	Current    int `json:"current_unique"`
	Registered int `json:"registered"`
	Tested     int `json:"current_tested"`
	Awaiting   int `json:"awaiting"`
	Excluded   int `json:"excluded"`
	Missing    int `json:"missing_job"`
}

type egressSourceRow struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	egressCoverageCounts
}

// All memberships for one identity share the same job. Compute the four
// disjoint states once, then fan the counts back out onto the displayed page.
const egressSourceCoverageSQL = `
WITH page AS (
 SELECT id,name FROM sources WHERE enabled=1 ORDER BY id LIMIT ? OFFSET ?
), ids AS MATERIALIZED (
 SELECT DISTINCT m.artifact_id AS identity FROM sources s JOIN memberships m ON m.source_id=s.id WHERE s.enabled=1
), states AS MATERIALIZED (
 SELECT k.identity, CASE
   WHEN x.identity IS NOT NULL OR g.state='BLOCKED' OR c.action='deleted' OR j.state='DELETED' THEN 'excluded'
   WHEN j.hash IS NULL THEN 'missing'
   WHEN j.tested>0 THEN 'tested' ELSE 'awaiting' END AS bucket
 FROM ids k LEFT JOIN egress_unique u ON u.identity=k.identity
 LEFT JOIN egress_jobs j ON j.hash=u.hash
 LEFT JOIN input_exclusions x ON x.identity=k.identity
 LEFT JOIN egress_iran_guard g ON g.identity=k.identity
 LEFT JOIN config_controls c ON c.id=k.identity AND c.expires>?
)
SELECT 0 AS scope,'' AS id,'' AS name,(SELECT count(*) FROM sources WHERE enabled=1),` + egressCoverageAggregates + ` FROM states v
UNION ALL SELECT 1,p.id,p.name,0,` + egressCoverageAggregates + ` FROM page p
 LEFT JOIN memberships m ON m.source_id=p.id LEFT JOIN states v ON v.identity=m.artifact_id
 GROUP BY p.id,p.name ORDER BY scope,id`

const egressCoverageAggregates = `count(v.identity),
 count(*) FILTER(WHERE v.bucket='tested'), count(*) FILTER(WHERE v.bucket='awaiting'),
 count(*) FILTER(WHERE v.bucket='excluded'), count(*) FILTER(WHERE v.bucket='missing')`

// A source may have a URL or a pasted configuration as its user-supplied
// label. Return only short, human-readable labels; its opaque ID still
// distinguishes sources that have the same or an omitted label.
func coverageSourceName(name string) string {
	if utf8.RuneCountInString(name) > 64 {
		return ""
	}
	for _, r := range name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != ' ' && r != '-' && r != '_' {
			return ""
		}
	}
	return name
}

func (m egressModule) sourceCoverage(w http.ResponseWriter, r *http.Request) {
	offset := 0
	if raw := r.URL.Query().Get("offset"); raw != "" {
		var err error
		offset, err = strconv.Atoi(raw)
		if err != nil || offset < 0 || offset > 1_000_000 {
			failure(w, ErrInvalid)
			return
		}
	}
	w.Header().Set("Cache-Control", "private, no-store")
	bounded, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	ctx, done, err := m.s.store.readSnapshot(bounded)
	if err != nil {
		failure(w, err)
		return
	}
	defer done()
	rows, err := m.s.store.read(ctx).QueryContext(ctx, egressSourceCoverageSQL, egressSourcePageSize, offset, readStamp(ctx))
	if err != nil {
		failure(w, err)
		return
	}
	defer rows.Close()
	var totalSources int
	var global egressCoverageCounts
	items := []egressSourceRow{}
	for rows.Next() {
		var row egressSourceRow
		var scope, total int
		if err = rows.Scan(&scope, &row.ID, &row.Name, &total, &row.Current, &row.Tested, &row.Awaiting, &row.Excluded, &row.Missing); err != nil {
			failure(w, err)
			return
		}
		row.Registered = row.Tested + row.Awaiting
		if scope == 0 {
			global, totalSources = row.egressCoverageCounts, total
		} else {
			row.Name = coverageSourceName(row.Name)
			items = append(items, row)
		}
	}
	if err = rows.Err(); err != nil {
		failure(w, err)
		return
	}
	respond(w, http.StatusOK, map[string]any{"as_of_ms": readStamp(ctx), "enabled_sources": totalSources,
		"global": global, "sources": items, "offset": offset, "page_size": egressSourcePageSize})
}
