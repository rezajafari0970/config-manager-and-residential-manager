package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"regexp"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/protocolpolicy"
	"go.yaml.in/yaml/v3"
)

var clashProfileList = regexp.MustCompile(`(?mi)(?:^|[{,])[\t ]*["']?(?:proxies|payload)["']?[\t ]*:`)

// Clash YAML is not an intake format. Inspect its proxy declarations so a
// private source response cannot retain excluded profiles outside normal intake.
func forbiddenClashProfile(ctx context.Context, raw []byte) bool {
	if !clashProfileList.Match(raw) {
		return false
	}
	decoder := yaml.NewDecoder(&contextReader{ctx, bytes.NewReader(raw)})
	for {
		var doc struct {
			Proxies yaml.Node `yaml:"proxies"`
			Payload yaml.Node `yaml:"payload"`
		}
		if err := decoder.Decode(&doc); err != nil {
			return err != io.EOF
		}
		for _, list := range []*yaml.Node{&doc.Proxies, &doc.Payload} {
			if list.Kind == yaml.AliasNode {
				list = list.Alias
			}
			if list == nil || list.Kind != yaml.SequenceNode {
				continue
			}
			for _, item := range list.Content {
				if item.Kind == yaml.AliasNode {
					item = item.Alias
				}
				if item == nil {
					return true
				}
				if item.Kind == yaml.ScalarNode {
					// The payload of a rule provider can contain ordinary routing rules.
					value := []byte(item.Value)
					if kind := kindOf(value); kind != "" && protocolpolicy.Disabled(kind, value) {
						return true
					}
					continue
				}
				var profile map[string]any
				if err := item.Decode(&profile); err != nil {
					return true
				}
				b, err := json.Marshal(profile)
				if err != nil || protocolpolicy.Disabled("", b) {
					return true
				}
			}
		}
	}
}
