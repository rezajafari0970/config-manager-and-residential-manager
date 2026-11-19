package egress

import (
	"encoding/json"

	nativedriver "github.com/rezajafari0970/config-manager-and-residential-manager/internal/native"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/probe"
)

const NativeID = nativedriver.NativeID
const NativeSHA = nativedriver.NativeSHA

func init() { Cores[NativeID] = NativeSHA }

func native(raw []byte) (Plan, bool) {
	plan, ok := nativedriver.Prepare(raw)
	if !ok {
		return Plan{}, false
	}
	p := Plan{Driver: "sing-box", Code: plan.Code, Format: "sing-box", Variants: []Variant{}}
	if len(plan.Candidates) != 1 {
		return p, true
	}
	original := raw
	if !json.Valid(original) {
		decoded, err := probe.DecodeEnvelope(raw)
		if err != nil || !json.Valid(decoded) {
			return p, false
		}
		original = decoded
	}
	template := plan.Candidates[0]
	p.Complete = true
	p.Variants = []Variant{{"raw", Hash(original), original}, {"template", template.SHA256, template.Config}}
	return p, true
}
