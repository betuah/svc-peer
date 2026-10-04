package endpoint

import (
	"context"
	"testing"

	"github.com/betuah/svc-peer/internal/protocol"
)

func TestCollectRanksPrivateHostBeforeSrflx(t *testing.T) {
	// Collect without STUN still returns ranked host candidates when interfaces exist.
	eps, err := Collect(context.Background(), 51820, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) == 0 {
		t.Skip("no non-loopback IPv4 interfaces in this environment")
	}
	for i := 1; i < len(eps); i++ {
		if protocol.IsUnderlayPrivate(eps[i].IP) && !protocol.IsUnderlayPrivate(eps[i-1].IP) {
			t.Fatalf("private host after non-private: %+v", eps)
		}
		if eps[i].Src == protocol.EndpointSrcHost && eps[i-1].Src == protocol.EndpointSrcSrflx {
			t.Fatalf("host after srflx: %+v", eps)
		}
	}
	for _, ep := range eps {
		if ep.Port != 51820 {
			t.Fatalf("port: %+v", ep)
		}
		if ep.Src != protocol.EndpointSrcHost {
			t.Fatalf("src without STUN should be host: %+v", ep)
		}
	}
}
