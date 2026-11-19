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
	Current                int `json:"current_unique"`
	Registered             int `json:"registered"`
	Tested                 int `json:"current_tested"`
	Awaiting               int `json:"awaiting"`
	Excluded               int `json:"excluded"`
	Missing                int `json:"missing_job"`
	Residential            int `json:"residential"`
	Published              int `json:"published"`
	WithdrawnAwaitingFirst int `json:"withdrawn_awaiting_first"`
}

type egressSourceRow struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	egressCoverageCounts
}

const currentEgressBucket = `CASE
   WHEN x.identity IS NOT NULL OR g.state='BLOCKED' OR c.action='deleted' OR j.state='DELETED' THEN 'excluded'
   WHEN j.hash IS NULL THEN 'missing'
   WHEN j.first_completed!=0 OR j.tested>0 THEN 'tested' ELSE 'awaiting' END`

const currentEgressJoins = `LEFT JOIN egress_unique u ON u.identity=k.identity
 LEFT JOIN egress_jobs j ON j.hash=u.hash
 LEFT JOIN input_exclusions x ON x.identity=k.identity
 LEFT JOIN egress_iran_guard g ON g.identity=k.identity
 LEFT JOIN config_controls c ON c.id=k.identity`

// All memberships for one identity share the same job. Compute the four
// disjoint states once, then fan the counts back out onto the displayed page.
const egressSourceCoverageSQL = `
SELECT * FROM (WITH page AS (
 SELECT id,name FROM sources WHERE enabled=1 ORDER BY id LIMIT ? OFFSET ?
), ids AS MATERIALIZED (
 SELECT DISTINCT m.artifact_id AS identity FROM sources s JOIN memberships m ON m.source_id=s.id WHERE s.enabled=1
),
 qualified AS MATERIALIZED (SELECT hash FROM egress_network_eligible),
 exported AS MATERIALIZED (SELECT hash FROM egress_export_eligible),
 states AS MATERIALIZED (
 SELECT k.identity,u.hash IN qualified AS residential,u.hash IN exported AS published, ` + currentEgressBucket + ` AS bucket
 FROM ids k ` + currentEgressJoins + ` AND c.expires>?3
), withdrawn AS MATERIALIZED (
 SELECT b.source_id,u.identity FROM egress_first_backlog b
 JOIN sources s ON s.id=b.source_id AND s.enabled=1
 JOIN egress_unique u ON u.hash=b.hash JOIN egress_jobs j ON j.hash=b.hash
 WHERE j.tested=0 AND j.first_completed=0 AND j.state!='DELETED'
 AND NOT EXISTS(SELECT 1 FROM memberships m WHERE m.source_id=b.source_id AND m.artifact_id=u.identity)
 AND NOT EXISTS(SELECT 1 FROM input_exclusions x WHERE x.identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_iran_guard g WHERE g.identity=u.identity AND g.state='BLOCKED')
 AND NOT EXISTS(SELECT 1 FROM config_controls c WHERE c.id=u.identity AND c.action='deleted' AND c.expires>?3)
)
SELECT 0 AS scope,'' AS id,'' AS name,(SELECT count(*) FROM sources WHERE enabled=1),` + egressCoverageAggregates + `,(SELECT count(DISTINCT identity) FROM withdrawn),
 (SELECT count(*) FROM qualified),(SELECT count(*) FROM exported) FROM states v
UNION ALL SELECT 1,p.id,p.name,0,` + egressCoverageAggregates + `,(SELECT count(*) FROM withdrawn w WHERE w.source_id=p.id),0,0 FROM page p
 LEFT JOIN memberships m ON m.source_id=p.id LEFT JOIN states v ON v.identity=m.artifact_id
 GROUP BY p.id,p.name ORDER BY scope,id)`

const egressCoverageAggregates = `count(v.identity),
 count(*) FILTER(WHERE v.bucket='tested'), count(*) FILTER(WHERE v.bucket='awaiting'),
 count(*) FILTER(WHERE v.bucket='excluded'), count(*) FILTER(WHERE v.bucket='missing'),
 count(*) FILTER(WHERE v.residential=1), count(*) FILTER(WHERE v.published=1)`

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
	db, err := freezeEgress(ctx, m.s.store.read(ctx))
	if err != nil {
		failure(w, err)
		return
	}
	rows, err := db.QueryContext(ctx, egressSourceCoverageSQL, egressSourcePageSize, offset, readStamp(ctx))
	if err != nil {
		failure(w, err)
		return
	}
	defer rows.Close()
	var totalSources, outsideResidential, outsidePublished int
	var global egressCoverageCounts
	items := []egressSourceRow{}
	for rows.Next() {
		var row egressSourceRow
		var scope, total, qualified, published int
		if err = rows.Scan(&scope, &row.ID, &row.Name, &total, &row.Current, &row.Tested, &row.Awaiting, &row.Excluded, &row.Missing, &row.Residential, &row.Published, &row.WithdrawnAwaitingFirst, &qualified, &published); err != nil {
			failure(w, err)
			return
		}
		row.Registered = row.Tested + row.Awaiting
		if scope == 0 {
			global, totalSources = row.egressCoverageCounts, total
			outsideResidential, outsidePublished = qualified-global.Residential, published-global.Published
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
		"global": global, "outside_active_sources": map[string]int{"residential": outsideResidential, "published": outsidePublished},
		"sources": items, "offset": offset, "page_size": egressSourcePageSize})
}
