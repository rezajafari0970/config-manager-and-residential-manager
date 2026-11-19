// config-compat applies qualified structural rules; it never certifies health.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/compat"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/protocolpolicy"
)

func main() {
	b, e := io.ReadAll(io.LimitReader(os.Stdin, 2*1024*1024+1))
	if e != nil || len(b) > 2*1024*1024 {
		fmt.Fprintln(os.Stderr, "input_size_or_read_error")
		os.Exit(2)
	}
	if protocolpolicy.Disabled("", b) {
		fmt.Fprintln(os.Stderr, protocolpolicy.Code)
		os.Exit(1)
	}
	out, _, e := compat.ApplyJSON(b)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	os.Stdout.Write(out)
}
