package main

import (
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/worker"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestWatchdogNotifiesConfiguredSocket(t *testing.T) {
	p := filepath.Join(t.TempDir(), "notify.sock")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: p, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("NOTIFY_SOCKET", p)
	worker.NotifySystemd("READY=1\nWATCHDOG=1")
	listener.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 128)
	n, _, err := listener.ReadFromUnix(b)
	if err != nil || string(b[:n]) != "READY=1\nWATCHDOG=1" {
		t.Fatal(n, err)
	}
	t.Setenv("NOTIFY_SOCKET", "")
	worker.NotifySystemd("WATCHDOG=1")
}
