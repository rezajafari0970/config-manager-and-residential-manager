package egress

import "sort"

const NetworkVersion = "ads-exit-network.v1"

// NetworkFact is produced inside the trusted worker while the reflected
// address still exists. Source is the same job-local HMAC as Sample.Source.
// No literal address or reconstructable host prefix leaves the worker.
type NetworkFact struct {
	Version      string `json:"version"`
	Kind         string `json:"kind"`
	Provider     string `json:"provider,omitempty"`
	ASN          uint32 `json:"asn,omitempty"`
	Family       int    `json:"family,omitempty"`
	PrefixLen    int    `json:"prefix_len,omitempty"`
	Source       string `json:"source,omitempty"`
	UsageSource  string `json:"usage_source,omitempty"`
	OriginSource string `json:"origin_source,omitempty"`
	Dataset      string `json:"dataset,omitempty"`
	CheckedAt    int64  `json:"checked_at,omitempty"`
	ValidUntil   int64  `json:"valid_until,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

// A separate publication decision preserves the route/health retention rules.
// Domain, Variant and Family identify the most important withholding observation.
type NetworkVerdict struct {
	Version         string   `json:"version"`
	State           string   `json:"state"`
	Reason          string   `json:"reason"`
	Detail          string   `json:"detail,omitempty"`
	Eligible        bool     `json:"eligible"`
	Until           int64    `json:"until"`
	Domain          string   `json:"domain,omitempty"`
	Variant         string   `json:"variant,omitempty"`
	Family          int      `json:"family,omitempty"`
	Provider        string   `json:"provider,omitempty"`
	Providers       []string `json:"providers,omitempty"`
	ASN             uint32   `json:"asn,omitempty"`
	Families        []int    `json:"families,omitempty"`
	DomainsObserved int      `json:"domains_observed"`
}

func networkSlug(s string) bool {
	if len(s) == 0 || len(s) > 96 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

func networkKind(s Sample, finished, now int64) string {
	n := s.Network
	if n == nil || n.Version != NetworkVersion || n.Source != s.Source || n.Family != s.Family ||
		(n.Kind != "hosting" && n.Kind != "access") || !networkSlug(n.Provider) || n.ASN == 0 ||
		n.PrefixLen < 1 || n.PrefixLen > 128 || (s.Family == 4 && n.PrefixLen > 32) ||
		!networkSlug(n.UsageSource) || !networkSlug(n.OriginSource) || n.UsageSource == n.OriginSource ||
		!routeHexBytes(n.Dataset, 32) || n.CheckedAt <= 0 || n.CheckedAt < s.At-2000 || n.CheckedAt > finished+2000 ||
		n.ValidUntil < s.At || n.ValidUntil <= now || n.ValidUntil <= n.CheckedAt ||
		n.ValidUntil-n.CheckedAt > EvidenceTTL {
		return "unknown"
	}
	return n.Kind
}

func networkRoundValid(r Report, hash string, now int64) bool {
	return r.Version == Version && r.Hash == hash && r.Started > 0 && r.Started >= now-300000 &&
		r.Finished >= r.Started && r.Finished <= now+2000 && len(r.Samples) <= 256
}

type networkScan struct {
	verdict                  NetworkVerdict
	domains                  map[string]bool
	families                 map[int]bool
	providers                map[string]bool
	accessOrigin             map[string]*NetworkFact
	selectedWaves            map[[2]string]map[int]bool
	access, hosting, unknown bool
	until                    int64
}

// An individual Ads flow can prove hosting despite a broken second variant or
// independent control. Attribution from such a failed attempt cannot grant access.
func (scan *networkScan) observe(r Report, plan Plan, variantHashes map[string]string, connections map[string]int, seen map[string]bool, selected bool, now int64) {
	if r.ResourcePressure || Cores[r.Core] == "" || Cores[r.Core] != r.CoreSHA || len(r.Checks) > 2 ||
		(plan.Driver != "xray" && plan.Driver != "sing-box") || (r.Core == NativeID) != (plan.Driver == "sing-box") {
		return
	}
	valid := map[string]bool{}
	for _, c := range r.Checks {
		hash, ok := variantHashes[c.Name]
		if _, duplicate := valid[c.Name]; duplicate || !ok {
			return
		}
		valid[c.Name] = c.Hash == hash && c.Core && routeHexBytes(c.RuntimeHash, 32) && (plan.Driver != "xray" || c.RuntimeHash == hash)
	}
	for _, s := range r.Samples {
		t, ok := targetFor(s.Domain)
		if !ok || t.Role != "ads" || !s.ActualAds || !valid[s.Variant] || s.Wave < 1 || s.Wave > 3 ||
			!validSource(s, r) || seen[s.Connection] {
			continue
		}
		seen[s.Connection] = true
		scan.domains[s.Domain], scan.families[s.Family] = true, true
		kind := networkKind(s, r.Finished, now)
		// A replay is neither an independent hosting signal nor permission to
		// discard a potentially conflicting Ads source and publish the others.
		if connections[s.Connection] != 1 || s.Code != "ads_peer_reported" || s.FirstStatus < 200 || s.FirstStatus >= 500 ||
			!s.ResponseComplete || s.RequestBytes <= 0 || s.RequestBytes > 32768 || s.ResponseBytes <= 0 || s.ResponseBytes > 131072 {
			kind = "unknown"
		}
		switch kind {
		case "hosting":
			scan.providers[s.Network.Provider] = true
			if !scan.hosting {
				scan.verdict.Domain, scan.verdict.Variant, scan.verdict.Family = s.Domain, s.Variant, s.Family
				scan.verdict.Provider, scan.verdict.ASN = s.Network.Provider, s.Network.ASN
				scan.verdict.Detail = ""
			}
			scan.hosting = true
		case "access":
			scan.providers[s.Network.Provider] = true
			if selected && s.Wave <= r.Waves {
				key := [2]string{s.Domain, s.Variant}
				if scan.selectedWaves[key] == nil {
					scan.selectedWaves[key] = map[int]bool{}
				}
				scan.selectedWaves[key][s.Wave] = true
			}
			// A single receipt uses one canonical lookup per source address. Two
			// incompatible access facts for that address cannot grant publication.
			if old := scan.accessOrigin[s.Source]; old != nil && (old.Provider != s.Network.Provider || old.ASN != s.Network.ASN || old.Family != s.Network.Family) {
				scan.unknown = true
			}
			scan.accessOrigin[s.Source] = s.Network
			scan.access = true
			scan.until = min(scan.until, s.Network.ValidUntil, s.At+EvidenceTTL)
		default:
			if !scan.unknown && !scan.hosting {
				scan.verdict.Domain, scan.verdict.Variant, scan.verdict.Family = s.Domain, s.Variant, s.Family
				if n := s.Network; n != nil && n.Version == NetworkVersion && n.Source == s.Source && n.Kind == "unknown" {
					switch n.Reason {
					case "network_snapshot_unavailable", "network_snapshot_invalid", "network_origin_expired", "network_origin_conflict", "network_origin_unavailable", "network_usage_unverified", "network_usage_expired", "network_usage_conflict", "network_source_invalid":
						scan.verdict.Detail = n.Reason
					}
				}
			}
			scan.unknown = true
		}
	}
}

func evaluateExitNetwork(r Report, p Plan, hash string, now int64, route Decision) NetworkVerdict {
	verdict := NetworkVerdict{Version: NetworkVersion, State: "unknown", Reason: "ads_network_receipt_unbound"}
	if !networkRoundValid(r, hash, now) || !p.Complete || len(p.Variants) != 2 || len(r.Evidence) > 4 ||
		p.Variants[0].Name != "raw" || p.Variants[1].Name != "template" {
		return verdict
	}
	hashes := map[string]string{}
	for _, v := range p.Variants {
		// A positive route has already verified both exact plan digests.
		if !route.Eligible && v.Hash != Hash(v.Config) {
			return verdict
		}
		hashes[v.Name] = v.Hash
	}
	scan := networkScan{
		verdict: verdict, domains: map[string]bool{}, families: map[int]bool{},
		providers: map[string]bool{}, accessOrigin: map[string]*NetworkFact{},
		selectedWaves: map[[2]string]map[int]bool{}, until: route.Until,
	}
	connections, seen := connectionCounts(r), map[string]bool{}
	scan.observe(r, p, hashes, connections, seen, true, now)
	for _, part := range r.Evidence {
		a, ok := resolveAttemptSamples(r, part)
		if ok && len(a.Evidence) == 0 && a.Started >= r.Started && a.Finished <= r.Finished && networkRoundValid(a, hash, now) {
			scan.observe(a, p, hashes, connections, seen, false, now)
		}
	}
	d := scan.verdict
	d.DomainsObserved = len(scan.domains)
	for provider := range scan.providers {
		d.Providers = append(d.Providers, provider)
	}
	sort.Strings(d.Providers)
	for _, family := range []int{4, 6} {
		if scan.families[family] {
			d.Families = append(d.Families, family)
		}
	}
	completePairs := 0
	for _, waves := range scan.selectedWaves {
		if len(waves) >= 2 {
			completePairs++
		}
	}
	switch {
	case scan.hosting && scan.access:
		d.State, d.Reason = "mixed", "ads_mixed_exit"
	case scan.hosting:
		d.State, d.Reason = "hosting", "ads_hosting_exit"
	case !scan.access || scan.unknown:
		d.Reason = "ads_network_evidence_incomplete"
	case !route.Eligible:
		d.Reason = "ads_network_route_unqualified"
	case len(route.QualifiedProfiles) != len(profiles) || completePairs != len(Domains)*2 || scan.until <= now:
		d.Reason = "ads_network_coverage_incomplete"
	default:
		d.State, d.Reason, d.Eligible, d.Until = "access", "ads_access_verified", true, scan.until
	}
	return d
}
