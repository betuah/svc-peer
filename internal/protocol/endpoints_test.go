package protocol

import "testing"

func TestIsUnderlayPrivate(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"192.168.1.10", true},
		{"172.16.5.1", true},
		{"100.64.0.1", true},
		{"100.127.255.255", true},
		{"169.254.1.1", true},
		{"fd12::1", true},
		{"8.8.8.8", false},
		{"1.2.3.4", false},
		{"127.0.0.1", false},
		{"0.0.0.0", false},
		{"not-an-ip", false},
		{"100.63.0.1", false},
		{"100.128.0.1", false},
	}
	for _, tc := range cases {
		if got := IsUnderlayPrivate(tc.ip); got != tc.want {
			t.Fatalf("%s: got %v want %v", tc.ip, got, tc.want)
		}
	}
}

func TestRankEndpointsPrefersPrivateHost(t *testing.T) {
	in := []Endpoint{
		{IP: "8.8.8.8", Port: 51820, Src: EndpointSrcSrflx},
		{IP: "203.0.113.5", Port: 51820, Src: EndpointSrcHost},
		{IP: "10.20.0.5", Port: 51820, Src: EndpointSrcHost},
		{IP: "192.168.0.2", Port: 51820, Src: EndpointSrcHost},
	}
	out := RankEndpoints(in)
	if out[0].IP != "10.20.0.5" && out[0].IP != "192.168.0.2" {
		t.Fatalf("first should be private host, got %+v", out[0])
	}
	if !IsUnderlayPrivate(out[0].IP) {
		t.Fatalf("first not private: %+v", out[0])
	}
	if out[len(out)-1].Src != EndpointSrcSrflx {
		t.Fatalf("srflx should be last: %+v", out)
	}
	pref := PreferredEndpoint(in)
	if pref != "10.20.0.5:51820" && pref != "192.168.0.2:51820" {
		t.Fatalf("preferred: %q", pref)
	}
}

func TestPreferredEndpointEmpty(t *testing.T) {
	if PreferredEndpoint(nil) != "" {
		t.Fatal("expected empty")
	}
}
