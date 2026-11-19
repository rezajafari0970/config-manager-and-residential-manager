package native

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func samples() []string {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	return []string{
		"tuic://11111111-1111-4111-8111-111111111111:secret@192.0.2.1:443?sni=example.com",
		"wireguard://" + key + "@192.0.2.1:51820?publickey=" + key + "&address=10.0.0.2%2F32&reserved=1,2,3&keepalive=25&dns=1.1.1.1",
	}
}
func TestNativeTemplatesAndPinnedCore(t *testing.T) {
	core := os.Getenv("SING_BOX_TEST_BINARY")
	if core != "" {
		b, e := os.ReadFile(core)
		if e != nil {
			t.Fatal(e)
		}
		h := sha256.Sum256(b)
		if hex.EncodeToString(h[:]) != NativeSHA {
			t.Fatal("wrong native core")
		}
	}
	for _, raw := range samples() {
		p, ok := Prepare([]byte(raw))
		if !ok || p.Code != "prepared" || len(p.Candidates) != 1 {
			t.Fatal("native preparation", p.Code)
		}
		c := p.Candidates[0]
		if c.Engine != "sing-box" || !c.RequiresConnection || bytes.Contains(c.Config, []byte(`"insecure":true`)) {
			t.Fatal("native evidence or TLS downgrade")
		}
		var m map[string]any
		if json.Unmarshal(c.Config, &m) != nil {
			t.Fatal("invalid native JSON")
		}
		if core != "" {
			path := filepath.Join(t.TempDir(), "config.json")
			os.WriteFile(path, c.Config, 0600)
			out, e := exec.Command(core, "check", "-c", path).CombinedOutput()
			if e != nil {
				t.Fatalf("native schema: %s", out)
			}
		}
	}
}
