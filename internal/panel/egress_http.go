package panel

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
	"io"
	"net/http"
	"strconv"
)

func (s *Store) registerPrivateEgress(mux *http.ServeMux) {
	mux.HandleFunc("POST /egress/claim", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Lane string `json:"lane"`
		}
		if decode(r, &request) != nil || (request.Lane != "" && request.Lane != "initial" && request.Lane != "followup") {
			failure(w, ErrInvalid)
			return
		}
		j, e := s.ClaimEgressLane(r.Context(), request.Lane)
		if e != nil {
			failure(w, e)
			return
		}
		respond(w, 200, j)
	})
	mux.HandleFunc("POST /egress/renew", func(w http.ResponseWriter, r *http.Request) {
		var j egress.Job
		if decode(r, &j) != nil {
			failure(w, ErrInvalid)
			return
		}
		if e := s.RenewEgress(r.Context(), j); e != nil {
			failure(w, e)
			return
		}
		respond(w, 200, true)
	})
	mux.HandleFunc("POST /egress/complete", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
		var c egress.Completion
		if decode(r, &c) != nil {
			failure(w, ErrInvalid)
			return
		}
		if e := s.CompleteEgress(r.Context(), c); e != nil {
			failure(w, e)
			return
		}
		respond(w, 200, true)
	})
	mux.HandleFunc("POST /egress/status", func(w http.ResponseWriter, r *http.Request) {
		var x struct {
			Status string `json:"status"`
			Code   string `json:"code"`
			Active int    `json:"active"`
		}
		if decode(r, &x) != nil || !safeCode(x.Status) || x.Active < 0 || x.Active > egress.MaxWorkers || x.Code != "" && !safeCode(x.Code) {
			failure(w, ErrInvalid)
			return
		}
		_, e := s.db.ExecContext(r.Context(), "UPDATE egress_worker SET status=?,heartbeat=?,active=?,code=? WHERE id=1", x.Status, egress.Now(), x.Active, x.Code)
		if e != nil {
			failure(w, e)
			return
		}
		respond(w, 200, true)
	})
}

type egressModule struct{ s *Server }

func (m egressModule) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /residential", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/egress", 303) })
	for _, path := range []string{"/api/residential", "/residential-subscription/", "/ads-different-subscription/"} {
		mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "retired feature; use the new Residential Ads page", 410)
		})
	}
	mux.HandleFunc("GET /api/egress", m.state)
	mux.HandleFunc("GET /api/egress/source-coverage", m.sourceCoverage)
	// Residential execution is automatic; no public manual queue mutation.

	mux.HandleFunc("POST /api/egress/countries", m.countries)
	mux.HandleFunc("POST /api/egress/lifecycle", m.lifecycle)
	mux.HandleFunc("GET /egress-subscription/datacenter-rejected/{token}/raw.txt", m.datacenterRejectedRaw)
	mux.HandleFunc("GET /egress-subscription/{token}/{format}", m.export)
}
func (m egressModule) links() map[string]string {
	out := map[string]string{}
	for _, f := range []string{"configs.json", "configs.jsonl", "next.json", "raw.txt"} {
		out[f] = m.s.origin + "/egress-subscription/" + m.s.store.digest("egress-export-v2", "all") + "/" + f
	}
	return out
}
func (m egressModule) state(w http.ResponseWriter, r *http.Request) {
	ctx, finish, e := m.s.store.readSnapshot(r.Context())
	if e != nil {
		failure(w, e)
		return
	}
	defer finish()
	db, e := freezeEgress(ctx, m.s.store.read(ctx))
	if e != nil {
		failure(w, e)
		return
	}
	counts := map[string]int{}
	rows, e := db.QueryContext(ctx, "SELECT state,count(*) FROM egress_inventory WHERE state!='DELETED' GROUP BY state")
	if e != nil {
		failure(w, e)
		return
	}
	for rows.Next() {
		var k string
		var n int
		if e = rows.Scan(&k, &n); e != nil {
			rows.Close()
			failure(w, e)
			return
		}
		counts[k] = n
	}
	if e = rows.Err(); e != nil {
		rows.Close()
		failure(w, e)
		return
	}
	rows.Close()
	var total, pending int
	if e = db.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(tested=0),0) FROM egress_inventory WHERE state!='DELETED'").Scan(&total, &pending); e != nil {
		failure(w, e)
		return
	}
	var status, code string
	var heartbeat int64
	var active int
	if e = db.QueryRowContext(ctx, "SELECT status,code,heartbeat,active FROM egress_worker").Scan(&status, &code, &heartbeat, &active); e != nil {
		failure(w, e)
		return
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	if offset > 1000000 {
		offset = 1000000
	}
	table := "egress_export_eligible"
	filter := ""
	publicationFlags := "1,1"
	if r.URL.Query().Get("view") == "diagnostics" {
		table = "egress_inventory"
		publicationFlags = `EXISTS(SELECT 1 FROM egress_network_eligible e WHERE e.hash=j.hash),
 EXISTS(SELECT 1 FROM egress_export_eligible e WHERE e.hash=j.hash)`
	}
	reportColumn := "report"
	if r.URL.Query().Get("brief") == "1" {
		reportColumn = "json_object('code',coalesce(json_extract(report,'$.code'),''))"
	}
	args := []any{}
	if hash := r.URL.Query().Get("hash"); hash != "" {
		if !validDigest(hash) {
			failure(w, ErrInvalid)
			return
		}
		filter += " AND hash=?"
		args = append(args, hash)
		offset = 0
	}
	args = append(args, offset)
	// Limit before joining private network receipts. A hold belongs to the
	// identity, while the latest assessment belongs to the exact tested bytes.
	query := `SELECT j.hash,j.kind,j.state,j.reason,j.revision,j.tested,j.valid_until,j.format,j.decision,j.proof,
 CASE WHEN n.hash=j.hash AND n.candidate_hash=j.candidate_hash AND n.checked_at=j.tested THEN n.summary ELSE '{}' END,
 coalesce(n.held,0),coalesce(n.clean_rounds,0),CASE WHEN n.held=1 THEN n.last_adverse ELSE '{}' END,` + publicationFlags + `
 FROM (SELECT hash,candidate_hash,kind,state,reason,revision,tested,valid_until,format,decision,` + reportColumn + ` AS proof
 FROM ` + table + ` WHERE state!='DELETED'` + filter + ` ORDER BY tested DESC,hash LIMIT 50 OFFSET ?) j
 LEFT JOIN egress_unique u ON u.hash=j.hash LEFT JOIN egress_network_results n ON n.identity=u.identity ORDER BY j.tested DESC,j.hash`
	rows, e = db.QueryContext(ctx, query, args...)
	if e != nil {
		failure(w, e)
		return
	}
	entries := []map[string]any{}
	for rows.Next() {
		var h, kind, state, reason, format, decision, report, network, adverse string
		var held, eligible, published bool
		var cleanRounds int
		var rev, tested, until int64
		if e = rows.Scan(&h, &kind, &state, &reason, &rev, &tested, &until, &format, &decision, &report, &network, &held, &cleanRounds, &adverse, &eligible, &published); e != nil {
			rows.Close()
			failure(w, e)
			return
		}
		var assessment map[string]json.RawMessage
		var lastAdverse egress.NetworkVerdict
		if e = json.Unmarshal([]byte(decision), &assessment); e == nil && held {
			e = json.Unmarshal([]byte(adverse), &lastAdverse)
		}
		if e != nil || assessment == nil || !json.Valid([]byte(network)) {
			rows.Close()
			failure(w, fmt.Errorf("invalid stored Ads assessment for %s", h))
			return
		}
		// Save the route-only verdict that older workers called RESIDENTIAL.
		// The projection retains all domain/transport details and unknown fields.
		route := map[string]json.RawMessage{
			"state": assessment["state"], "reason": assessment["reason"], "route": assessment["route"],
			"qualified_at_test": assessment["eligible"], "valid_until": assessment["until"],
		}
		if string(route["state"]) == `"RESIDENTIAL"` {
			route["state"] = json.RawMessage(`"ADS_SPLIT"`)
		}
		if state == "RESIDENTIAL" && !eligible {
			state = "ADS_SPLIT"
			switch {
			case held:
				reason = "ads_hosting_exit"
				if lastAdverse.State == "mixed" {
					reason = "ads_mixed_exit"
				}
			case until <= readStamp(ctx):
				reason = "ads_proof_expired"
			default:
				reason = "ads_route_ineligible"
			}
		}
		if !eligible {
			until = 0
		}
		assessment["network"] = json.RawMessage(network)
		assessment["state"], _ = json.Marshal(state)
		assessment["reason"], _ = json.Marshal(reason)
		assessment["eligible"], _ = json.Marshal(eligible)
		assessment["until"], _ = json.Marshal(until)
		assessment["published"], _ = json.Marshal(published)
		entries = append(entries, map[string]any{"hash": h, "kind": kind, "state": state, "route_assessment": route,
			"network": json.RawMessage(network), "network_held": held, "network_clean_rounds": cleanRounds, "last_adverse": json.RawMessage(adverse),
			"residential_eligible": eligible, "published": published, "reason": reason, "revision": rev, "tested": tested, "valid_until": until, "format": format, "decision": assessment, "report": json.RawMessage(report)})
	}
	if e = rows.Err(); e != nil {
		rows.Close()
		failure(w, e)
		return
	}
	rows.Close()
	for _, entry := range entries {
		names := []string{}
		owners, err := db.QueryContext(ctx, "SELECT DISTINCT s.name FROM sources s JOIN memberships m ON m.source_id=s.id JOIN egress_unique u ON u.identity=m.artifact_id WHERE u.hash=? ORDER BY s.name", entry["hash"])
		if err != nil {
			failure(w, err)
			return
		}
		for owners.Next() {
			var name string
			if err = owners.Scan(&name); err != nil {
				owners.Close()
				failure(w, err)
				return
			}
			names = append(names, name)
		}
		if err = owners.Err(); err != nil {
			owners.Close()
			failure(w, err)
			return
		}
		owners.Close()
		entry["sources"] = names
		countries, err := entryCountries(ctx, db, entry["hash"].(string))
		if err != nil {
			failure(w, err)
			return
		}
		entry["countries"] = countries
		var health string
		var checked, valid int64
		if err = db.QueryRowContext(ctx, "SELECT status,checked_at,valid_until FROM egress_health WHERE hash=?", entry["hash"]).Scan(&health, &checked, &valid); err == nil {
			entry["health"] = map[string]any{"status": health, "checked_at": checked, "valid_until": valid, "fresh": valid > readStamp(ctx)}
		} else if err != sql.ErrNoRows {
			failure(w, err)
			return
		}
	}
	var partial int
	if e = db.QueryRowContext(ctx, "SELECT count(*) FROM egress_inventory WHERE state!='DELETED' AND json_extract(decision,'$.route')='PARTIAL_DIFFERENCE'").Scan(&partial); e != nil {
		failure(w, e)
		return
	}
	var completed, definitive, completed10, definitive10, unique5, unique10, conclusive5, conclusive10, firstSettled5, previouslySettled5 int
	now := readStamp(ctx)
	start5 := now - 300000
	if e = db.QueryRowContext(ctx, `SELECT coalesce(sum(e.at>?),0),coalesce(sum(e.at>? AND e.definitive=1),0),count(*),coalesce(sum(e.definitive),0),
 count(DISTINCT CASE WHEN e.at>? THEN e.hash END),count(DISTINCT e.hash),
 count(DISTINCT CASE WHEN e.at>? AND e.definitive=1 THEN e.hash END),count(DISTINCT CASE WHEN e.definitive=1 THEN e.hash END),
 count(DISTINCT CASE WHEN e.at>? AND e.definitive=1 AND s.at>? AND s.at<=? THEN e.hash END),
 count(DISTINCT CASE WHEN e.at>? AND e.definitive=1 AND s.at<=? THEN e.hash END)
 FROM egress_events e LEFT JOIN egress_settlements s ON s.hash=e.hash WHERE e.at>? AND e.at<=?`, start5, start5, start5, start5, start5, start5, now, start5, start5, now-600000, now).
		Scan(&completed, &definitive, &completed10, &definitive10, &unique5, &unique10, &conclusive5, &conclusive10, &firstSettled5, &previouslySettled5); e != nil {
		failure(w, e)
		return
	}
	metrics, err := egressMetricState(ctx, db)
	if err != nil {
		failure(w, err)
		return
	}
	var recovery int
	if e = db.QueryRowContext(ctx, "SELECT count(*) FROM egress_work WHERE paused=0 AND token!='' AND lease_until<=?", now).Scan(&recovery); e != nil {
		failure(w, e)
		return
	}
	countryInfo, err := countryState(ctx, db)
	if err != nil {
		failure(w, err)
		return
	}
	lifecycle, err := lifecycleState(ctx, db)
	if err != nil {
		failure(w, err)
		return
	}
	accounting, err := egressAccounting(ctx, db)
	if err != nil {
		failure(w, err)
		return
	}
	queue := accounting["queue"].(map[string]int)
	due, activeLeases := queue["due"], queue["running"]
	run, err := egressRunState(ctx, db)
	if err != nil {
		failure(w, err)
		return
	}
	missing := accounting["coverage_missing"]
	pub := accounting["publication"].(map[string]int)
	retained, eligible := pub["retained"], pub["eligible"]
	counts["ADS_SPLIT"] += counts["RESIDENTIAL"] - eligible
	counts["RESIDENTIAL"] = eligible
	iran, err := iranState(ctx, db, readStamp(ctx))
	if err != nil {
		failure(w, err)
		return
	}
	profileStats, err := egressProfileSummary(ctx, db)
	if err != nil {
		failure(w, err)
		return
	}
	var dcRejected int
	if e = db.QueryRowContext(ctx, "SELECT count(*) "+datacenterRejectedFrom).Scan(&dcRejected); e != nil {
		failure(w, e)
		return
	}
	respond(w, 200, map[string]any{"datacenter_rejections": map[string]any{"count": dcRejected, "raw_url": m.datacenterRejectedURL()}, "profile_stats": profileStats, "profiles": egress.Profiles(), "rescan": run, "now": readStamp(ctx), "accounting": accounting, "iran_guard": iran, "metrics": metrics, "queue": map[string]any{"due": due, "recoverable_leases": recovery, "active_leases": activeLeases}, "lifecycle": lifecycle, "coverage_missing": missing, "retained": retained, "country": countryInfo, "throughput": map[string]any{"target_5m": 500, "first_settled_5m": firstSettled5, "previously_settled_5m": previouslySettled5, "settlement_unknown_5m": conclusive5 - firstSettled5 - previouslySettled5, "unique_definitive_5m": conclusive5, "unique_definitive_10m": conclusive10, "unique_5m": unique5, "unique_10m": unique10, "completed_5m": completed, "definitive_5m": definitive, "completed_10m": completed10, "definitive_10m": definitive10, "target_10m": 1000, "max_workers": egress.MaxWorkers}, "version": egress.Version, "total": total, "pending": pending, "partial": partial, "eligible": eligible, "counts": counts, "entries": entries, "offset": offset, "links": m.links(), "domains": egress.Domains, "targets": egress.Targets(), "worker": map[string]any{"status": status, "heartbeat": heartbeat, "active": active, "code": code}, "classification": "At least one complete Ads profile must pass the route and delivery checks in raw and template. A verified datacenter exit blocks publication unless the specific flow is proven to share the ordinary controls outside the qualifying profile. Shared hosting is reported separately. Unknown network ownership alone does not block it.", "scope": "TCP HTTP/1.1 / versioned Ads profiles / same-family stable controls including ordinary Google / raw and template; source-unobservable controls and QUIC remain unknown"})
}

type egressExportEntry struct {
	Hash          string
	Candidate     string
	Until         int64 `json:"-"`
	Format        string
	Countries     []string
	Coverage      string
	Profiles      []string
	SharedHosting []egressSharedHost
}

func egressSnapshot(ctx context.Context, q databaseQuery) ([]egressExportEntry, string, error) {
	// Read membership and country history in one statement. The final check runs
	// under the writer reservation, so a query per config would delay renewals.
	rows, e := q.QueryContext(ctx, `SELECT e.hash,e.candidate_hash,min(e.valid_until,e.network_valid_until,g.valid_until,c.last_seen+?),e.format,c.country,
 coalesce(json_extract(e.decision,'$.ads_coverage'),''),coalesce(json_extract(e.decision,'$.qualified_profiles'),'[]'),
 coalesce(json_extract(n.summary,'$.shared_hosting'),'[]')
 FROM egress_export_eligible e JOIN egress_geo_results g ON g.hash=e.hash
 JOIN egress_unique u ON u.hash=e.hash LEFT JOIN egress_network_results n
 ON n.identity=u.identity AND n.hash=e.hash AND n.candidate_hash=e.candidate_hash AND n.checked_at=e.tested
 JOIN egress_countries c ON c.hash=e.hash AND c.last_seen>? ORDER BY e.hash,c.country`, egress.CountryWindow, readStamp(ctx)-egress.CountryWindow)
	if e != nil {
		return nil, "", e
	}
	defer rows.Close()
	out := []egressExportEntry{}
	for rows.Next() {
		var x egressExportEntry
		var country, profiles, shared string
		if e = rows.Scan(&x.Hash, &x.Candidate, &x.Until, &x.Format, &country, &x.Coverage, &profiles, &shared); e != nil {
			return nil, "", e
		}
		if len(out) == 0 || out[len(out)-1].Hash != x.Hash {
			if e = json.Unmarshal([]byte(profiles), &x.Profiles); e != nil {
				return nil, "", e
			}
			if e = json.Unmarshal([]byte(shared), &x.SharedHosting); e != nil {
				return nil, "", e
			}
			out = append(out, x)
		}
		entry := &out[len(out)-1]
		entry.Until = min(entry.Until, x.Until)
		entry.Countries = append(entry.Countries, country)
	}
	if e = rows.Err(); e != nil {
		return nil, "", e
	}
	rows.Close()
	var revision int64
	if e = q.QueryRowContext(ctx, "SELECT revision FROM egress_country_policy WHERE id=1").Scan(&revision); e != nil {
		return nil, "", e
	}
	b, _ := json.Marshal(struct {
		Revision int64
		Entries  []egressExportEntry
	}{revision, out})
	return out, egress.Hash(b), nil
}
func (m egressModule) export(w http.ResponseWriter, r *http.Request) { m.exportAttempt(w, r, 0) }
func (m egressModule) exportAttempt(w http.ResponseWriter, r *http.Request, attempt int) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Ads-Iran-Guard", egress.IranVersion+"; IR-veto; observed-only")
	if !equal(r.PathValue("token"), m.s.store.digest("egress-export-v2", "all")) {
		http.NotFound(w, r)
		return
	}
	format := r.PathValue("format")
	if format != "configs.json" && format != "configs.jsonl" && format != "next.json" && format != "raw.txt" {
		http.NotFound(w, r)
		return
	}
	entries, generation, e := egressSnapshot(r.Context(), m.s.store.reader())
	if e != nil {
		failure(w, e)
		return
	}
	if len(entries) == 0 {
		http.Error(w, "no eligible Ads configuration for the current route, datacenter and country policy", 503)
		return
	}
	if g := r.URL.Query().Get("generation"); g != "" && g != generation {
		http.Error(w, "generation changed", 409)
		return
	}
	var chosen string
	if format == "next.json" {
		e = m.s.store.read(r.Context()).QueryRowContext(r.Context(), "SELECT e.hash FROM egress_export_eligible e LEFT JOIN egress_turns t ON t.hash=e.hash ORDER BY coalesce(t.turn,0),e.hash LIMIT 1").Scan(&chosen)
		if e != nil {
			failure(w, e)
			return
		}
	}
	spool, e := newExportSpool()
	if e != nil {
		failure(w, e)
		return
	}
	defer spool.Close()
	spool.array = format == "configs.json"
	count := 0
	size := int64(0)
	formats := map[string]bool{}
	for _, x := range entries {
		if chosen != "" && chosen != x.Hash {
			continue
		}
		hash := x.Candidate
		if format == "raw.txt" {
			hash = x.Hash
		}
		b, e := m.s.store.openExportBlob(hash)
		if e != nil {
			http.Error(w, "publication bytes unavailable", 503)
			return
		}
		body, e := io.ReadAll(io.LimitReader(b, 8<<20))
		b.Close()
		if e != nil || egress.Hash(body) != hash {
			http.Error(w, "publication bytes invalid", 503)
			return
		}
		if format != "raw.txt" && !json.Valid(body) {
			http.Error(w, "invalid export structure", 503)
			return
		}
		size += int64(len(body))
		if size > 256<<20 {
			http.Error(w, "export too large", 503)
			return
		}
		if e = spool.Line(body); e != nil {
			failure(w, e)
			return
		}
		count++
		formats[x.Format] = true
	}
	if e = spool.Rewind(); e != nil {
		failure(w, e)
		return
	}
	tx, e := m.s.store.outputTransaction(r.Context())
	if e != nil {
		failure(w, e)
		return
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(r.Context(), "UPDATE egress_settings SET generation=generation WHERE id=1"); e != nil {
		failure(w, e)
		return
	}
	finalEntries, current, e := egressSnapshot(r.Context(), tx)
	if e != nil {
		failure(w, e)
		return
	}
	var deadline int64
	for _, entry := range finalEntries {
		if deadline == 0 || entry.Until < deadline {
			deadline = entry.Until
		}
	}
	if current != generation || deadline <= egress.Now() {
		if attempt < 2 && r.URL.Query().Get("generation") == "" {
			tx.Rollback()
			spool.Close()
			m.exportAttempt(w, r, attempt+1)
			return
		}
		http.Error(w, "eligibility changed", 409)
		return
	}
	if chosen != "" && r.Method != http.MethodHead {
		var first string
		e = tx.QueryRowContext(r.Context(), "SELECT e.hash FROM egress_export_eligible e LEFT JOIN egress_turns t ON t.hash=e.hash ORDER BY coalesce(t.turn,0),e.hash LIMIT 1").Scan(&first)
		if e != nil || first != chosen {
			if attempt < 2 && r.URL.Query().Get("generation") == "" {
				tx.Rollback()
				spool.Close()
				m.exportAttempt(w, r, attempt+1)
				return
			}
			http.Error(w, "rotation advanced; retry", 409)
			return
		}
		_, e = tx.ExecContext(r.Context(), "INSERT INTO egress_turns VALUES(?,(SELECT coalesce(max(turn),0)+1 FROM egress_turns)) ON CONFLICT(hash) DO UPDATE SET turn=excluded.turn", chosen)
		if e != nil {
			failure(w, e)
			return
		}
	}
	if deadline <= egress.Now() {
		http.Error(w, "eligibility expired", http.StatusServiceUnavailable)
		return
	}
	if e = tx.Commit(); e != nil {
		failure(w, e)
		return
	}
	// A delayed commit cannot extend a proof to the start of delivery.
	if deadline <= egress.Now() {
		http.Error(w, "eligibility expired", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if format == "configs.json" || format == "next.json" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.Header().Set("Content-Disposition", "inline")
	w.Header().Set("X-Egress-Generation", generation)
	w.Header().Set("X-Country-Policy", "any-observed-country-selected; 24h; GeoIP-estimate")
	w.Header().Set("X-Config-Count", strconv.Itoa(count))
	w.Header().Set("X-Residential-Definition", "verified-ads-profile-split")
	w.Header().Set("X-Egress-Profile-Policy", "any-complete-profile; partial-Ads-coverage-explicit")
	w.Header().Set("X-Egress-Network-Policy", "datacenter-veto; proven-shared-control-flow-reported-separately")
	setEgressScopeHeaders(w.Header(), finalEntries, chosen)
	w.Header().Set("X-Egress-Evidence", "authenticated-Ads-peer-reported; finite TCP scope")
	w.Header().Set("X-Config-Formats", fmt.Sprint(formats))
	w.Header().Set("X-Content-SHA256", spool.Hash())
	if r.Method != http.MethodHead {
		spool.WriteTo(w)
	}
}
