package probe

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
	"net/url"
	"strings"
)

// DecodeEnvelope unwraps representations, never guesses an encryption key. It
// keeps the immutable original outside this function and bounds nesting/bytes.
func DecodeEnvelope(raw []byte) ([]byte, error) {
	b := bytes.TrimSpace(raw)
	mustJSON := false
	for depth := 0; depth < 6; depth++ {
		if len(b) > repair.MaxBytes {
			return nil, errors.New("inspection_size_limit")
		}
		if len(b) == 0 {
			return nil, errors.New("custom_json_envelope_invalid")
		}
		if b[0] == '{' {
			return b, nil
		}
		if b[0] == '"' {
			mustJSON = true
			var s string
			if json.Unmarshal(b, &s) != nil {
				return nil, errors.New("custom_json_envelope_invalid")
			}
			b = []byte(s)
			continue
		}
		s := string(b)
		scheme, payload, wrapped := strings.Cut(s, "://")
		switch strings.ToLower(scheme) {
		case "json", "custom", "napsternet":
			if wrapped {
				mustJSON = true
				s = strings.SplitN(payload, "#", 2)[0]
			}
		default:
			if wrapped {
				if mustJSON {
					return nil, errors.New("custom_json_envelope_invalid")
				}
				return b, nil
			}
		}
		if strings.Contains(s, "%") {
			v, e := url.PathUnescape(s)
			if e != nil {
				return nil, errors.New("custom_json_envelope_invalid")
			}
			if v != s {
				b = []byte(v)
				continue
			}
		}
		decoded, e := decode(s)
		if e != nil {
			if !wrapped && !mustJSON {
				return b, nil
			}
			return nil, errors.New("custom_json_envelope_invalid")
		}
		b = bytes.TrimSpace(decoded)
	}
	return nil, errors.New("custom_json_envelope_depth")
}
