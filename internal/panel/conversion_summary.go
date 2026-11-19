package panel

import (
	"context"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/convert"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
	"strings"
)

type CoverageExclusion struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

type SourceConversionSummary struct {
	Excluded          []CoverageExclusion `json:"excluded,omitempty"`
	Coverage          ConversionCoverage  `json:"coverage"`
	Prepared          int                 `json:"prepared"`
	NativeReady       int                 `json:"native_ready"`
	NativePrepared    int                 `json:"native_prepared"`
	PreparationFailed int                 `json:"preparation_failed"`
	Total             int                 `json:"total"`
	Ready             int                 `json:"ready"`
	Connected         int                 `json:"connected"`
	Repaired          int                 `json:"repaired"`
	Pending           int                 `json:"pending"`
	Blocked           int                 `json:"blocked"`
	Issues            map[string]int      `json:"issues,omitempty"`
}

// Use the same representative ranking and source membership as Output, then
// aggregate canonical identities, not every historical raw representation.
func (s *Store) SourceConversionSummaries(ctx context.Context, sources []Source) (map[string]SourceConversionSummary, error) {
	out := map[string]SourceConversionSummary{}
	if len(sources) == 0 {
		return out, nil
	}
	seen := map[string]map[string]bool{}
	now := readStamp(ctx)
	end := strings.LastIndex(conversionQuery, "\n SELECT ")
	q := conversionQuery[:end]
	q = strings.Replace(q, " SELECT ", " SELECT m.source_id,r.version AS result_version,r.rule AS result_rule,", 1)
	q = strings.Replace(q, "PARTITION BY a.id", "PARTITION BY m.source_id,a.id", 1)
	marks := make([]string, len(sources))
	args := conversionQueryArgs(now)
	for i, source := range sources {
		marks[i] = "?"
		args = append(args, source.ID)
		out[source.ID] = SourceConversionSummary{}
		seen[source.ID] = map[string]bool{}
	}
	q = strings.Replace(q, "/* source filter */", "AND m.source_id IN ("+strings.Join(marks, ",")+")", 1)
	q += ` SELECT source_id,id,coalesce(result_version,''),coalesce(result_rule,''),coalesce(state,'queued'),coalesce(code,''),coalesce(available,0),coalesce(connection,''),coalesce(valid_until,0),coalesce((SELECT candidate_hash FROM template_preparations p WHERE p.hash=choices.raw_hash AND p.version='` + convert.Version + `'),''),coalesce((SELECT engine FROM template_preparations p WHERE p.hash=choices.raw_hash AND p.version='` + convert.Version + `'),''),coalesce((SELECT code FROM template_preparations p WHERE p.hash=choices.raw_hash AND p.version='` + convert.Version + `'),'')  ,coalesce(core,'not_run'),coalesce(tested,0),coalesce(candidate_hash,'') FROM choices WHERE choice=1`
	rows, err := s.read(ctx).QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, identity string
		var version, rule, state, code, connection string
		var preparedHash, engine, prepCode, core, candidate string
		var tested int64
		var available bool
		var validUntil int64
		if err = rows.Scan(&id, &identity, &version, &rule, &state, &code, &available, &connection, &validUntil, &preparedHash, &engine, &prepCode, &core, &tested, &candidate); err != nil {
			return nil, err
		}
		v := out[id]
		seen[id][identity] = true
		v.Total++
		v.Coverage.Add(Conversion{Current: version == convert.Version, State: state, Code: code, Core: core, Connection: connection, ValidUntil: validUntil, Tested: tested, CandidateHash: candidate, Prepared: preparedHash != "", PreparationCode: prepCode}, now)
		if preparedHash != "" {
			v.Prepared++
			if engine == "sing-box" {
				v.NativePrepared++
			}
		} else if prepCode != "" {
			v.PreparationFailed++
		}
		nativeHealthy := engine == "sing-box" && version == convert.Version && connection == "passed" && validUntil > now
		if nativeHealthy {
			v.NativeReady++
		}
		if available || nativeHealthy {
			v.Ready++
			if connection == "passed" && validUntil > now {
				v.Connected++
			}
			if strings.HasPrefix(rule, convert.Version+"."+repair.RulesVersion) {
				v.Repaired++
			}
		}
		if version != convert.Version || state == "queued" || state == "running" {
			v.Pending++
		} else if !available && !nativeHealthy {
			v.Blocked++
			if code == "" {
				code = "structural_unresolved"
			}
			if v.Issues == nil {
				v.Issues = map[string]int{}
			}
			v.Issues[code]++
		}
		out[id] = v
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	// Enumerate the same current inventory shown on each source card, including
	// paused and safety-gated members. Never silently count those as pending.
	inventoryArgs := []any{now, now}
	for _, source := range sources {
		inventoryArgs = append(inventoryArgs, source.ID)
	}
	inventory, err := s.read(ctx).QueryContext(ctx, `SELECT m.source_id,m.artifact_id,(s.enabled=0 OR EXISTS(SELECT 1 FROM config_controls c WHERE c.id=a.id AND c.expires>?)) FROM memberships m JOIN artifacts a ON a.id=m.artifact_id JOIN sources s ON s.id=m.source_id WHERE a.expires>? AND m.source_id IN (`+strings.Join(marks, ",")+`) ORDER BY m.source_id,m.artifact_id`, inventoryArgs...)
	if err != nil {
		return nil, err
	}
	defer inventory.Close()
	for inventory.Next() {
		var id, identity string
		var paused bool
		if err = inventory.Scan(&id, &identity, &paused); err != nil {
			return nil, err
		}
		if seen[id][identity] {
			continue
		}
		v := out[id]
		reason := "safety_policy"
		if paused {
			v.Coverage.Paused++
			reason = "paused"
		} else {
			v.Coverage.Withheld++
		}
		v.Coverage.Total++
		v.Excluded = append(v.Excluded, CoverageExclusion{ID: identity, Reason: reason})
		out[id] = v
	}
	return out, inventory.Err()
}
