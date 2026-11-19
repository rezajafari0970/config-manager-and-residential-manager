package collect

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestWireGuardEntersAllSubscriptionFormatsExactly(t *testing.T) {
	raw := []byte("wg://synthetic@192.0.2.1:51820?address=192.0.2.2%2F32#unchanged\r\n")
	for _, body := range [][]byte{raw, []byte(base64.StdEncoding.EncodeToString(raw))} {
		values, kinds, e := extractTest(t, body)
		if e != nil || len(values) != 1 || kinds[0] != "wg" || !bytes.Equal(values[0], raw) {
			t.Fatal("native acquisition lost bytes", e, kinds)
		}
	}
}
