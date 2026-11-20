// Package side binds a service qualification to both the received input and
// the template a subscriber can use. It never substitutes an alternate route
// or a repair hypothesis for the original input.
package side

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/convert"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/probe"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
)

func Prepare(raw []byte) probe.Plan {
	p := convert.Prepare(raw)
	if len(p.Candidates) == 0 {
		return p
	}
	source, err := probe.DecodeExactEnvelope(raw)
	if err != nil {
		return p
	}
	if bytes.HasPrefix(bytes.TrimSpace(source), []byte("{")) {
		if json.Valid(source) {
			p.RawCandidate = &probe.Candidate{Engine: p.Candidates[0].Engine, Rule: "received_json",
				SHA256: repair.Digest(source), Config: source, RequiresConnection: true}
		}
		return p
	}
	// A share URI describes an outbound, not an executable JSON envelope.
	// Use its original import representation. Native WireGuard imports have
	// one deterministic representation and no alternate route hypotheses.
	if c := p.Candidates[0]; c.Engine == "sing-box" && len(p.Candidates) == 1 {
		p.RawCandidate = &c
		return p
	}
	imported := probe.Prepare(source)
	if imported.RawIssue != "" || len(imported.Candidates) == 0 {
		return p
	}
	c := imported.Candidates[0]
	if strings.Contains(c.Rule, "hypothesis") || strings.Contains(c.Rule, "uri-userinfo-space") {
		return p
	}
	p.RawCandidate = &c
	return p
}
