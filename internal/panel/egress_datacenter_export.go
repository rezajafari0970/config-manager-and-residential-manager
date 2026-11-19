package panel

import (
	"context"
	"net/http"
)

// A hold records a verified hosting or mixed Ads exit for this identity.
// Unknown follow-ups retain the hold. The current raw representative must have
// an assessment of its own. Country selection is only for residential outputs.
const datacenterRejectedFrom = `FROM egress_network_results n
 CROSS JOIN egress_unique u ON u.identity=n.identity AND u.hash=n.hash
 CROSS JOIN egress_jobs j ON j.hash=u.hash
 WHERE n.held=1 AND j.paused=0 AND j.state!='DELETED'
 AND (SELECT enabled FROM egress_settings WHERE id=1)=1
 AND NOT EXISTS(SELECT 1 FROM egress_owners o JOIN input_exclusions x ON x.identity=o.identity WHERE o.hash=u.hash)
 AND NOT EXISTS(SELECT 1 FROM egress_owners o JOIN egress_iran_guard g ON g.identity=o.identity WHERE o.hash=u.hash)
 AND NOT EXISTS(SELECT 1 FROM egress_owners o JOIN config_controls c ON c.id=o.identity WHERE o.hash=u.hash AND c.expires>CAST(unixepoch('subsec')*1000 AS INTEGER))
 AND u.hash NOT IN (SELECT hash FROM egress_jobs WHERE json_extract(decision,'$.country_conflict')=1)
 AND NOT EXISTS(SELECT 1 FROM egress_retirements r WHERE r.hash=u.hash)`

func datacenterRejectedEntries(ctx context.Context, q readQuerier) ([]networkEntry, error) {
	rows, err := q.QueryContext(ctx, "SELECT u.identity,u.hash "+datacenterRejectedFrom+" ORDER BY u.identity")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []networkEntry
	for rows.Next() {
		var row networkEntry
		if err := rows.Scan(&row.ID, &row.Hash); err != nil {
			return nil, err
		}
		entries = append(entries, row)
	}
	return entries, rows.Err()
}

func (m egressModule) datacenterRejectedURL() string {
	return m.s.origin + "/egress-subscription/datacenter-rejected/" + m.s.store.digest("egress-export-v2", "datacenter-rejected") + "/raw.txt"
}

func (m egressModule) datacenterRejectedRaw(w http.ResponseWriter, r *http.Request) {
	if !equal(r.PathValue("token"), m.s.store.digest("egress-export-v2", "datacenter-rejected")) {
		http.NotFound(w, r)
		return
	}
	m.s.verifiedRaw(w, r, rawScope{datacenterRejected: true})
}
