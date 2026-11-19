package panel

import (
	"context"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// Counts use the same read snapshot and authoritative eligibility views as the
// panel and exports. Profile counts may overlap; identity totals never do.
func egressProfileSummary(ctx context.Context, q databaseQuery) (map[string]any, error) {
	var complete, partial, published int
	if err := q.QueryRowContext(ctx, `SELECT coalesce(sum(json_extract(decision,'$.ads_coverage')='ALL_TESTED'),0),coalesce(sum(json_extract(decision,'$.ads_coverage')='PARTIAL'),0),(SELECT count(*) FROM egress_export_eligible) FROM egress_eligible`).Scan(&complete, &partial, &published); err != nil {
		return nil, err
	}
	rows, err := q.QueryContext(ctx, `SELECT p.value,count(*) FROM egress_eligible e,json_each(e.decision,'$.qualified_profiles') p GROUP BY p.value`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err = rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		counts[id] = n
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return map[string]any{"complete_tested_ads": complete, "partial_tested_ads": partial, "published": published, "profiles": counts, "profile_counts_overlap": true, "profile_count_scope": "qualifying_route_receipts"}, nil
}

// Only public destination and network names belong in subscription headers.
// Per-flow evidence, including the variant, stays available in the panel.
type egressSharedHost struct {
	Domain   string `json:"domain"`
	Provider string `json:"provider"`
}

func setEgressScopeHeaders(header http.Header, entries []egressExportEntry, chosen string) {
	profiles := make(map[string]int)
	shared := make(map[string]bool)
	partial := 0
	for _, entry := range entries {
		if chosen != "" && entry.Hash != chosen {
			continue
		}
		for _, profile := range entry.Profiles {
			profiles[profile]++
		}
		if entry.Coverage == "PARTIAL" {
			partial++
		}
		for _, flow := range entry.SharedHosting {
			shared[flow.Domain+"="+flow.Provider] = true
		}
	}
	counts := make([]string, 0, len(profiles))
	for _, profile := range slices.Sorted(maps.Keys(profiles)) {
		counts = append(counts, profile+"="+strconv.Itoa(profiles[profile]))
	}
	header.Set("X-Egress-Qualified-Profile-Counts", strings.Join(counts, ", "))
	header.Set("X-Egress-Partial-Profile-Count", strconv.Itoa(partial))
	// Bound the union for bulk subscriptions; the per-entry API retains every pair.
	var observed []string
	size := 0
	for _, pair := range slices.Sorted(maps.Keys(shared)) {
		if size+len(pair)+2 > 2048 {
			header.Set("X-Egress-Shared-Hosting-Truncated", "true")
			break
		}
		observed = append(observed, pair)
		size += len(pair) + 2
	}
	if len(observed) > 0 {
		header.Set("X-Egress-Shared-Hosting", strings.Join(observed, ", "))
	}
}
