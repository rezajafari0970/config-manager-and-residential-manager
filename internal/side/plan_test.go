package side

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
)

func TestPlanBindsSourceObjectIndependentlyOfTemplate(t *testing.T) {
	source := []byte("  " + `{"inbounds":[],"outbounds":[{"tag":"original","protocol":"shadowsocks","settings":{"servers":[{"address":"192.0.2.10","port":443,"method":"aes-128-gcm","password":"fixture"}]}}]}` + "\n")
	raw := []byte("json://" + base64.RawURLEncoding.EncodeToString(source))
	p := Prepare(raw)
	if len(p.Candidates) == 0 || p.RawCandidate == nil || p.RawCandidate.SHA256 != repair.Digest(source) ||
		!bytes.Equal(p.RawCandidate.Config, source) || p.OriginalSHA256 != repair.Digest(raw) || p.Candidates[0].SHA256 == p.RawCandidate.SHA256 {
		t.Fatal("source bytes conflated with a normalized or repaired runtime")
	}
}
