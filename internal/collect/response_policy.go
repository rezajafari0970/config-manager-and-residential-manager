package collect

import (
	"bytes"
	"context"
	"errors"
	"io"
	"regexp"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/protocolpolicy"
	"go.yaml.in/yaml/v3"
)

var errSourceDisabled = errors.New("source contains disabled protocol")
var clashProfileList = regexp.MustCompile(`(?mi)(?:^|[{,])[\t ]*["']?(?:proxies|payload)["']?[\t ]*:`)

// SourceResponseDisabled inspects the original and its decoded subscription
// envelopes. Clash YAML is not ingested, but its bytes can still be downloaded.
func SourceResponseDisabled(ctx context.Context, path string) (bool, error) {
	registry := NewRegistry()
	registry.inspectDocument = func(raw []byte) error {
		if !clashProfileList.Match(raw) {
			return nil
		}
		type proxy struct {
			Type string `yaml:"type"`
		}
		decoder := yaml.NewDecoder(&contextReader{ctx, bytes.NewReader(raw)})
		for {
			var doc struct {
				Proxies yaml.Node `yaml:"proxies"`
				Payload yaml.Node `yaml:"payload"`
			}
			err := decoder.Decode(&doc)
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return errSourceDisabled
			}
			for _, list := range []*yaml.Node{&doc.Proxies, &doc.Payload} {
				if list.Kind == yaml.AliasNode {
					list = list.Alias
				}
				if list.Kind != yaml.SequenceNode {
					continue
				}
				for _, item := range list.Content {
					if item.Kind == yaml.AliasNode {
						item = item.Alias
					}
					// Rule providers also contain ordinary scalar rules.
					if item.Kind == yaml.ScalarNode {
						if protocolpolicy.Disabled("", []byte(item.Value)) {
							return errSourceDisabled
						}
						continue
					}
					var p proxy
					if item.Decode(&p) != nil || protocolpolicy.DisabledKind(p.Type) {
						return errSourceDisabled
					}
				}
			}
		}
	}
	err := registry.Extract(ctx, path, func(_ context.Context, item io.Reader, kind string) error {
		blocked, err := protocolpolicy.DisabledReader(kind, item)
		if blocked {
			return errSourceDisabled
		}
		return err
	})
	if errors.Is(err, errSourceDisabled) {
		return true, nil
	}
	return false, err
}
