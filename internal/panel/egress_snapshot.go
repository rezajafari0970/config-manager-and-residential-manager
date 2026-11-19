package panel

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SQLite's wall clock is statement-scoped, even inside a read transaction.
// Inline the authoritative view definitions with one presentation timestamp so
// counts, country membership and entries cannot disagree at a TTL boundary.
type egressSnapshotReader struct {
	q           databaseQuery
	eligibility string
	queue       string
}

func (r egressSnapshotReader) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return r.q.QueryContext(ctx, r.query(q), args...)
}
func (r egressSnapshotReader) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	return r.q.QueryRowContext(ctx, r.query(q), args...)
}

// Scope only the caller's inventory/work reads. Never shadow the authoritative
// views inside eligibility: correlated eligibility lookups must keep their hash
// index. Globally replacing those views previously multiplied the sparse scan
// for every candidate and country lookup.
var egressPresentationScope = regexp.MustCompile(`\begress_(inventory|work)\b`)

func (r egressSnapshotReader) query(q string) string {
	if !egressPresentationScope.MatchString(q) {
		return r.eligibility + q
	}
	scoped := `egress_presentation_scope(hash) AS MATERIALIZED (` + egressInventoryCandidates + `),
 egress_presentation_inventory AS NOT MATERIALIZED (SELECT j.* FROM egress_presentation_scope c CROSS JOIN egress_frozen_inventory j ON j.hash=c.hash),
 egress_presentation_work AS NOT MATERIALIZED (SELECT j.* FROM egress_presentation_scope c CROSS JOIN egress_frozen_work j ON j.hash=c.hash),`
	q = egressPresentationScope.ReplaceAllString(q, "egress_presentation_$1")
	return "WITH " + r.queue + "," + scoped + strings.TrimPrefix(r.eligibility, "WITH ") + q
}

var egressViewBody = regexp.MustCompile(`(?i)\bAS\s+(?:SELECT|WITH)\b`)

func freezeEgress(ctx context.Context, q databaseQuery) (databaseQuery, error) {
	stamp := strconv.FormatInt(readStamp(ctx), 10)
	rows, err := q.QueryContext(ctx, `SELECT name,sql FROM sqlite_schema WHERE type='view' AND name IN
 ('egress_eligible','egress_network_eligible','egress_geo_eligible','egress_export_eligible','egress_inventory','egress_work','egress_retirement_work')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var eligibility, queue []string
	for rows.Next() {
		var name, definition string
		if err := rows.Scan(&name, &definition); err != nil {
			return nil, err
		}
		match := egressViewBody.FindStringIndex(definition)
		if match == nil {
			return nil, fmt.Errorf("invalid residential view: %s", name)
		}
		body := strings.TrimSuffix(strings.TrimSpace(definition[match[0]+2:]), ";")
		body = strings.ReplaceAll(body, "CAST(unixepoch('subsec')*1000 AS INTEGER)", stamp)
		if name == "egress_retirement_work" {
			queue = append(queue, name+" AS NOT MATERIALIZED ("+body+")")
		} else if egressPresentationScope.MatchString(name) {
			// The work view reads inventory. Both must use the same clock, but
			// only their outermost callers need the sparse candidate scope.
			body = egressPresentationScope.ReplaceAllString(body, "egress_frozen_$1")
			frozenName := egressPresentationScope.ReplaceAllString(name, "egress_frozen_$1")
			queue = append(queue, frozenName+" AS NOT MATERIALIZED ("+body+")")
		} else {
			eligibility = append(eligibility, name+" AS ("+body+")")
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(queue) != 3 || len(eligibility) != 4 {
		return nil, fmt.Errorf("incomplete residential snapshot views")
	}
	return egressSnapshotReader{q: q, eligibility: "WITH " + strings.Join(eligibility, ",") + " ", queue: strings.Join(queue, ",")}, nil
}
