package egress

import (
	"slices"
	"sort"
)

const NetworkVersion = "ads-exit-network.v1"
const NetworkPolicyVersion = "ads-exit-network-policy.v2"

// NetworkFact is produced inside the trusted worker while the reflected
// address still exists. Source is the same job-local HMAC as Sample.Source.
// No literal address or reconstructable host prefix leaves the worker.
type NetworkFact struct {
	Version              string `json:"version"`
	Kind                 string `json:"kind"`
	Provider             string `json:"provider,omitempty"`
	ASN                  uint32 `json:"asn,omitempty"`
	Family               int    `json:"family,omitempty"`
	PrefixLen            int    `json:"prefix_len,omitempty"`
	Source               string `json:"source,omitempty"`
	UsageSource          string `json:"usage_source,omitempty"`
	OriginSource         string `json:"origin_source,omitempty"`
	Dataset              string `json:"dataset,omitempty"`
	CheckedAt            int64  `json:"checked_at,omitempty"`
	ValidUntil           int64  `json:"valid_until,omitempty"`
	Reason               string `json:"reason,omitempty"`
	OriginOutsideHosting bool   `json:"origin_outside_hosting,omitempty"`
}

// NetworkFlow identifies an observed Ads connection scope without retaining the
// source address or its job-local token.
type NetworkFlow struct {
	Domain  string `json:"domain"`
	Variant string `json:"variant"`
	Family  int    `json:"family"`
}

type NetworkFlowOrigin struct {
	NetworkFlow
	ASN uint32 `json:"asn"`
}

// Eligible describes positive access attribution only. The residential route
// policy uses BlocksResidential; unclassified traffic does not add a veto.
type NetworkVerdict struct {
	Version           string              `json:"version"`
	Policy            string              `json:"policy,omitempty"`
	State             string              `json:"state"`
	Reason            string              `json:"reason"`
	Detail            string              `json:"detail,omitempty"`
	Eligible          bool                `json:"eligible"`
	Until             int64               `json:"until"`
	Domain            string              `json:"domain,omitempty"`
	Variant           string              `json:"variant,omitempty"`
	Family            int                 `json:"family,omitempty"`
	Provider          string              `json:"provider,omitempty"`
	Providers         []string            `json:"providers,omitempty"`
	ASN               uint32              `json:"asn,omitempty"`
	Families          []int               `json:"families,omitempty"`
	DomainsObserved   int                 `json:"domains_observed"`
	HostingFlows      []NetworkFlow       `json:"hosting_flows,omitempty"`
	SharedHosting     []SharedNetwork     `json:"shared_hosting,omitempty"`
	UnresolvedHosting []SharedNetwork     `json:"unresolved_hosting,omitempty"`
	SharedFlows       []NetworkFlow       `json:"shared_flows,omitempty"`
	HostingASNs       []uint32            `json:"hosting_asns,omitempty"`
	OutsideOrigins    []NetworkFlowOrigin `json:"outside_origins,omitempty"`
	ClearedFlows      []NetworkFlow       `json:"cleared_flows,omitempty"`
	ClearanceUntil    int64               `json:"clearance_until,omitempty"`
}

func (n NetworkVerdict) BlocksResidential() bool {
	return n.Version == NetworkVersion && (n.State == "hosting" || n.State == "mixed")
}

// ClearsHosting applies only to an identity already held for observed hosting.
// Access on an unrelated path, family, or variant cannot clear that history.
func (n NetworkVerdict) ClearsHosting(previous NetworkVerdict) bool {
	if n.Version != NetworkVersion || n.BlocksResidential() || n.ClearanceUntil <= 0 || !previous.BlocksResidential() {
		return false
	}
	flows := previous.HostingFlows
	if len(flows) == 0 {
		// Older verdicts retained a single specific adverse flow.
		flows = []NetworkFlow{{previous.Domain, previous.Variant, previous.Family}}
	}
	for _, flow := range flows {
		if slices.Contains(n.ClearedFlows, flow) || slices.Contains(n.SharedFlows, flow) {
			continue
		}
		if previous.ASN == 0 && len(previous.HostingASNs) == 0 {
			return false
		}
		matched := false
		for _, observed := range n.OutsideOrigins {
			if observed.NetworkFlow != flow {
				continue
			}
			if observed.ASN == 0 || observed.ASN == previous.ASN || slices.Contains(previous.HostingASNs, observed.ASN) {
				return false
			}
			matched = true
		}
		if !matched {
			return false
		}
	}
	return true
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
		n.ASN == 0 ||
		n.PrefixLen < 1 || n.PrefixLen > 128 || (s.Family == 4 && n.PrefixLen > 32) ||
		!routeHexBytes(n.Dataset, 32) || n.CheckedAt <= 0 || n.CheckedAt < s.At-2000 || n.CheckedAt > finished+2000 ||
		n.ValidUntil < s.At || n.ValidUntil <= now || n.ValidUntil <= n.CheckedAt ||
		n.ValidUntil-n.CheckedAt > EvidenceTTL {
		return "unknown"
	}
	if n.OriginOutsideHosting {
		publicOrigin := n.ASN < 4_200_000_000 && n.ASN != 23456 && (n.ASN < 64496 || n.ASN > 65551)
		if publicOrigin && n.Kind == "unknown" && n.Reason == "network_usage_unverified" &&
			n.UsageSource == "" && n.Provider == "" && n.OriginSource == "ripe-ris" {
			return "outside"
		}
		return "unknown"
	}
	if (n.Kind != "hosting" && n.Kind != "access") || !networkSlug(n.Provider) || !networkSlug(n.UsageSource) || !networkSlug(n.OriginSource) || n.UsageSource == n.OriginSource {
		return "unknown"
	}
	return n.Kind
}

type networkScan struct {
	verdict                  NetworkVerdict
	domains                  map[string]bool
	families                 map[int]bool
	providers                map[string]bool
	origins                  map[string]*NetworkFact
	flows                    map[NetworkFlow]*networkFlowEvidence
	conflictingSources       map[string]bool
	access, hosting, unknown bool
}

// Only the selected core can clear a previous adverse flow. Other attempts can
// reveal a hosting observation or an unresolved observation of that same flow.
type networkFlowEvidence struct {
	selectedShared map[int]bool
	unshared       bool
	hosting        bool
	unknown        bool
	sources        []string
	outsideASNs    []uint32
	waves          map[int]bool
	until          int64
}

// A hosting network and a separated route require independent evidence.
// Confirm the same hosting attribution in two paired waves of one core attempt.
func (scan *networkScan) observe(r Report, plan Plan, variantHashes map[string]string, connections map[string]int, seen map[string]bool, selected bool, now int64) {
	if r.ResourcePressure || !boundCore(plan.Driver, r.Core, r.CoreSHA) || len(r.Checks) > 2 {
		return
	}
	valid := map[string]bool{}
	for _, c := range r.Checks {
		hash, ok := variantHashes[c.Name]
		if _, duplicate := valid[c.Name]; duplicate || !ok {
			return
		}
		valid[c.Name] = boundCheck(c, hash)
	}
	if r.Waves < 1 || r.Waves > 3 {
		return
	}
	controls := readOrdinaryControls(r, valid, connections)
	hostingWaves := map[SharedNetwork]map[int]bool{}
	var hostingOrder []SharedNetwork
	for _, s := range r.Samples {
		t, ok := targetFor(s.Domain)
		if !ok || t.Role != "ads" || !s.ActualAds || !valid[s.Variant] || !routeValid(s, r) || seen[s.Connection] {
			continue
		}
		seen[s.Connection] = true
		scan.domains[s.Domain], scan.families[s.Family] = true, true
		flow := NetworkFlow{s.Domain, s.Variant, s.Family}
		evidence := scan.flows[flow]
		if evidence == nil {
			evidence = &networkFlowEvidence{}
			scan.flows[flow] = evidence
		}
		// A replay cannot prove either hosting or recovery.
		path, kind := pathUnresolved, "unknown"
		if connections[s.Connection] == 1 && verifiedAdsExchange(s) {
			path = controls.path(s)
			kind = networkKind(s, r.Finished, now)
		}
		if path == pathShared {
			if selected {
				if evidence.selectedShared == nil {
					evidence.selectedShared = map[int]bool{}
				}
				evidence.selectedShared[s.Wave] = true
			}
		} else {
			evidence.unshared = true
		}
		switch kind {
		case "hosting":
			hit := SharedNetwork{flow, s.Network.Provider, s.Network.ASN}
			if path == pathShared {
				if !slices.Contains(scan.verdict.SharedHosting, hit) {
					scan.verdict.SharedHosting = append(scan.verdict.SharedHosting, hit)
				}
				continue
			}
			if hostingWaves[hit] == nil {
				hostingWaves[hit] = map[int]bool{}
				hostingOrder = append(hostingOrder, hit)
			}
			if path == pathSeparated {
				hostingWaves[hit][s.Wave] = true
			}
		case "access", "outside":
			if kind == "access" {
				scan.providers[s.Network.Provider] = true
				scan.access = true
			} else {
				if !scan.unknown && !scan.hosting {
					scan.verdict.Domain, scan.verdict.Variant, scan.verdict.Family = s.Domain, s.Variant, s.Family
					scan.verdict.Detail = s.Network.Reason
				}
				scan.unknown = true
			}
			if !slices.Contains(evidence.sources, s.Source) {
				evidence.sources = append(evidence.sources, s.Source)
			}
			if kind == "outside" && !slices.Contains(evidence.outsideASNs, s.Network.ASN) {
				evidence.outsideASNs = append(evidence.outsideASNs, s.Network.ASN)
			}
			if selected {
				expires := min(s.Network.ValidUntil, s.At+EvidenceTTL)
				if evidence.waves == nil {
					evidence.waves = map[int]bool{}
					evidence.until = expires
				}
				evidence.until = min(evidence.until, expires)
				evidence.waves[s.Wave] = true
			}
			// A single receipt uses one canonical lookup per source address. Two
			// incompatible facts for that address cannot clear an earlier hold.
			if old := scan.origins[s.Source]; old != nil && (old.Provider != s.Network.Provider || old.ASN != s.Network.ASN || old.Family != s.Network.Family) {
				scan.unknown = true
				scan.conflictingSources[s.Source] = true
			}
			scan.origins[s.Source] = s.Network
		default:
			evidence.unknown = true
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
	for _, hit := range hostingOrder {
		evidence := scan.flows[hit.NetworkFlow]
		if len(hostingWaves[hit]) < 2 {
			evidence.unknown = true
			scan.unknown = true
			if !slices.Contains(scan.verdict.UnresolvedHosting, hit) {
				scan.verdict.UnresolvedHosting = append(scan.verdict.UnresolvedHosting, hit)
			}
			continue
		}
		evidence.hosting = true
		if !slices.Contains(scan.verdict.HostingASNs, hit.ASN) {
			scan.verdict.HostingASNs = append(scan.verdict.HostingASNs, hit.ASN)
		}
		scan.providers[hit.Provider] = true
		if !scan.hosting {
			scan.verdict.Domain, scan.verdict.Variant, scan.verdict.Family = hit.Domain, hit.Variant, hit.Family
			scan.verdict.Provider, scan.verdict.ASN = hit.Provider, hit.ASN
			scan.verdict.Detail = ""
		}
		scan.hosting = true
	}
}

func evaluateExitNetwork(r Report, p Plan, hash string, now int64, route Decision) NetworkVerdict {
	verdict := NetworkVerdict{Policy: NetworkPolicyVersion, Version: NetworkVersion, State: "unknown", Reason: "ads_network_receipt_unbound"}
	if !boundRound(r, hash, now) || !p.Complete || len(p.Variants) != 2 || len(r.Evidence) > 4 ||
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
		providers: map[string]bool{}, origins: map[string]*NetworkFact{},
		flows: map[NetworkFlow]*networkFlowEvidence{}, conflictingSources: map[string]bool{},
	}
	connections, seen := connectionCounts(r), map[string]bool{}
	scan.observe(r, p, hashes, connections, seen, true, now)
	for _, part := range r.Evidence {
		a, ok := resolveAttemptSamples(r, part)
		if ok && len(a.Evidence) == 0 && a.Started >= r.Started && a.Finished <= r.Finished && boundRound(a, hash, now) {
			scan.observe(a, p, hashes, connections, seen, false, now)
		}
	}
	d := scan.verdict
	slices.Sort(d.HostingASNs)
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
	verified := map[[2]string]bool{}
	for _, domain := range Domains {
		for _, variant := range []string{"raw", "template"} {
			for _, family := range []int{4, 6} {
				key := NetworkFlow{domain, variant, family}
				flow := scan.flows[key]
				if flow == nil {
					continue
				}
				if len(flow.selectedShared) >= 2 && !flow.unshared {
					d.SharedFlows = append(d.SharedFlows, key)
					if d.ClearanceUntil == 0 {
						d.ClearanceUntil = route.Until
					}
				}
				if flow.hosting {
					d.HostingFlows = append(d.HostingFlows, key)
				} else if route.Eligible && !flow.unknown && len(flow.waves) >= 2 && !slices.ContainsFunc(flow.sources, func(source string) bool { return scan.conflictingSources[source] }) {
					if len(flow.outsideASNs) > 0 {
						slices.Sort(flow.outsideASNs)
						for _, asn := range flow.outsideASNs {
							d.OutsideOrigins = append(d.OutsideOrigins, NetworkFlowOrigin{key, asn})
						}
					} else {
						d.ClearedFlows = append(d.ClearedFlows, key)
						verified[[2]string{domain, variant}] = true
					}
					if d.ClearanceUntil == 0 {
						d.ClearanceUntil = route.Until
					}
					d.ClearanceUntil = min(d.ClearanceUntil, flow.until)
				}
			}
		}
	}
	profileAccess := false
	for _, profile := range profiles {
		if !slices.Contains(route.QualifiedProfiles, profile.ID) {
			continue
		}
		complete := true
		for _, domain := range profile.Domains {
			complete = complete && verified[[2]string{domain, "raw"}] && verified[[2]string{domain, "template"}]
		}
		profileAccess = profileAccess || complete
	}
	switch {
	case scan.hosting && scan.access:
		d.State, d.Reason = "mixed", "ads_mixed_exit"
	case scan.hosting:
		d.State, d.Reason = "hosting", "ads_hosting_exit"
	case len(d.UnresolvedHosting) > 0:
		d.Reason = "ads_hosting_route_unresolved"
	case !scan.access || scan.unknown:
		d.Reason = "ads_network_evidence_incomplete"
	case !route.Eligible:
		d.Reason = "ads_network_route_unqualified"
	case !profileAccess || d.ClearanceUntil <= now:
		d.Reason = "ads_network_coverage_incomplete"
	default:
		d.State, d.Reason, d.Eligible, d.Until = "access", "ads_access_verified", true, d.ClearanceUntil
	}
	return d
}
