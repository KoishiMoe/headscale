package types

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/opt"
)

func Test_NodeCanAccess(t *testing.T) {
	iap := func(ipStr string) *netip.Addr {
		ip := netip.MustParseAddr(ipStr)
		return &ip
	}
	tests := []struct {
		name  string
		node1 Node
		node2 Node
		rules []tailcfg.FilterRule
		want  bool
	}{
		{
			name: "no-rules",
			node1: Node{
				IPv4: iap("10.0.0.1"),
			},
			node2: Node{
				IPv4: iap("10.0.0.2"),
			},
			rules: []tailcfg.FilterRule{},
			want:  false,
		},
		{
			name: "wildcard",
			node1: Node{
				IPv4: iap("10.0.0.1"),
			},
			node2: Node{
				IPv4: iap("10.0.0.2"),
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"*"},
					DstPorts: []tailcfg.NetPortRange{
						{
							IP:    "*",
							Ports: tailcfg.PortRangeAny,
						},
					},
				},
			},
			want: true,
		},
		{
			name: "other-cant-access-src",
			node1: Node{
				IPv4: iap("100.64.0.1"),
			},
			node2: Node{
				IPv4: iap("100.64.0.3"),
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.2/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.3/32", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			want: false,
		},
		{
			name: "dest-cant-access-src",
			node1: Node{
				IPv4: iap("100.64.0.3"),
			},
			node2: Node{
				IPv4: iap("100.64.0.2"),
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.2/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.3/32", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			want: false,
		},
		{
			name: "src-can-access-dest",
			node1: Node{
				IPv4: iap("100.64.0.2"),
			},
			node2: Node{
				IPv4: iap("100.64.0.3"),
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.2/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.3/32", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			want: true,
		},
		// Subnet-to-subnet tests.
		// When ACL src and dst are both subnet CIDRs, subnet
		// routers advertising those subnets must see each other.
		{
			name: "subnet-to-subnet-src-router-sees-dst-router-3157",
			node1: Node{
				IPv4: iap("100.64.0.1"),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("10.88.8.0/24"),
					},
				},
				ApprovedRoutes: []netip.Prefix{
					netip.MustParsePrefix("10.88.8.0/24"),
				},
			},
			node2: Node{
				IPv4: iap("100.64.0.2"),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("10.99.9.0/24"),
					},
				},
				ApprovedRoutes: []netip.Prefix{
					netip.MustParsePrefix("10.99.9.0/24"),
				},
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"10.88.8.0/24"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "10.99.9.0/24", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			want: true,
		},
		{
			// With a unidirectional ACL (src=A→dst=B), the dst
			// router cannot access the src router. Bidirectional
			// peer visibility comes from BuildPeerMap checking
			// both A.CanAccess(B) || B.CanAccess(A).
			name: "subnet-to-subnet-unidirectional-dst-cannot-access-src-3157",
			node1: Node{
				IPv4: iap("100.64.0.2"),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("10.99.9.0/24"),
					},
				},
				ApprovedRoutes: []netip.Prefix{
					netip.MustParsePrefix("10.99.9.0/24"),
				},
			},
			node2: Node{
				IPv4: iap("100.64.0.1"),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("10.88.8.0/24"),
					},
				},
				ApprovedRoutes: []netip.Prefix{
					netip.MustParsePrefix("10.88.8.0/24"),
				},
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"10.88.8.0/24"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "10.99.9.0/24", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			want: false,
		},
		{
			// With a bidirectional ACL, both routers can access
			// each other.
			name: "subnet-to-subnet-bidirectional-3157",
			node1: Node{
				IPv4: iap("100.64.0.2"),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("10.99.9.0/24"),
					},
				},
				ApprovedRoutes: []netip.Prefix{
					netip.MustParsePrefix("10.99.9.0/24"),
				},
			},
			node2: Node{
				IPv4: iap("100.64.0.1"),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("10.88.8.0/24"),
					},
				},
				ApprovedRoutes: []netip.Prefix{
					netip.MustParsePrefix("10.88.8.0/24"),
				},
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"10.88.8.0/24"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "10.99.9.0/24", Ports: tailcfg.PortRangeAny},
					},
				},
				{
					SrcIPs: []string{"10.99.9.0/24"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "10.88.8.0/24", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			want: true,
		},
		{
			name: "subnet-to-subnet-regular-node-excluded-3157",
			node1: Node{
				IPv4: iap("100.64.0.3"),
			},
			node2: Node{
				IPv4: iap("100.64.0.2"),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("10.99.9.0/24"),
					},
				},
				ApprovedRoutes: []netip.Prefix{
					netip.MustParsePrefix("10.99.9.0/24"),
				},
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"10.88.8.0/24"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "10.99.9.0/24", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			want: false,
		},
		{
			name: "subnet-to-subnet-unrelated-router-excluded-3157",
			node1: Node{
				IPv4: iap("100.64.0.3"),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("172.16.0.0/24"),
					},
				},
				ApprovedRoutes: []netip.Prefix{
					netip.MustParsePrefix("172.16.0.0/24"),
				},
			},
			node2: Node{
				IPv4: iap("100.64.0.2"),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("10.99.9.0/24"),
					},
				},
				ApprovedRoutes: []netip.Prefix{
					netip.MustParsePrefix("10.99.9.0/24"),
				},
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"10.88.8.0/24"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "10.99.9.0/24", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matchers := matcher.MatchesFromFilterRules(tt.rules)
			got := tt.node1.CanAccess(matchers, &tt.node2)

			if got != tt.want {
				t.Errorf("canAccess() failed: want (%t), got (%t)", tt.want, got)
			}
		})
	}
}

// Test_NodeCanAccess_Unidirectional asserts that a one-way rule grants
// access in one direction only. A unidirectional ACL is a valid and
// intentional pattern; the "OR" aggregation in the v1 compat harness
// loses this asymmetry, which motivated the directional split in
// TestRoutesCompatPeerVisibility.
func Test_NodeCanAccess_Unidirectional(t *testing.T) {
	iap := func(ipStr string) *netip.Addr {
		ip := netip.MustParseAddr(ipStr)
		return &ip
	}

	nodeA := Node{IPv4: iap("100.64.0.1")}
	nodeB := Node{IPv4: iap("100.64.0.2")}

	rules := []tailcfg.FilterRule{
		{
			SrcIPs: []string{"100.64.0.1/32"},
			DstPorts: []tailcfg.NetPortRange{
				{IP: "100.64.0.2/32", Ports: tailcfg.PortRangeAny},
			},
		},
	}

	matchers := matcher.MatchesFromFilterRules(rules)

	if !nodeA.CanAccess(matchers, &nodeB) {
		t.Errorf("A→B: want true, got false")
	}

	if nodeB.CanAccess(matchers, &nodeA) {
		t.Errorf("B→A: want false, got true (unidirectional rule leaked reverse access)")
	}
}

func TestNodeFQDN(t *testing.T) {
	tests := []struct {
		name    string
		node    Node
		domain  string
		want    string
		wantErr string
	}{
		{
			name: "no-dnsconfig-with-username",
			node: Node{
				GivenName: "test",
				User: &User{
					Name: "user",
				},
			},
			domain: "example.com",
			want:   "test.example.com.",
		},
		{
			name: "all-set",
			node: Node{
				GivenName: "test",
				User: &User{
					Name: "user",
				},
			},
			domain: "example.com",
			want:   "test.example.com.",
		},
		{
			name: "no-given-name",
			node: Node{
				User: &User{
					Name: "user",
				},
			},
			domain:  "example.com",
			wantErr: "creating valid FQDN: node has no given name",
		},
		{
			name: "too-long-username",
			node: Node{
				GivenName: strings.Repeat("a", 256),
			},
			domain:  "example.com",
			wantErr: fmt.Sprintf("creating valid FQDN (%s.example.com.): hostname too long, cannot accept more than 255 ASCII chars", strings.Repeat("a", 256)),
		},
		{
			name: "no-dnsconfig",
			node: Node{
				GivenName: "test",
				User: &User{
					Name: "user",
				},
			},
			domain: "example.com",
			want:   "test.example.com.",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.node.GetFQDN(tc.domain)

			t.Logf("GOT: %q, %q", got, tc.domain)

			if (err != nil) && (err.Error() != tc.wantErr) {
				t.Errorf("GetFQDN() error = %s, wantErr %s", err, tc.wantErr)

				return
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("GetFQDN unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestValidateGivenName(t *testing.T) {
	tests := []struct {
		name       string
		givenName  string
		baseDomain string
		wantErr    bool
	}{
		{"valid", "test", "example.com", false},
		{"empty", "", "example.com", true},
		{"invalid label chars", "not valid", "example.com", true},
		{"label too long", strings.Repeat("a", 64), "example.com", true},
		// A valid 63-char label whose FQDN overflows only because the base
		// domain is long: ValidLabel passes, the FQDN-length bound rejects it.
		{"fqdn too long under long base domain", strings.Repeat("a", 63), strings.Repeat("b", 200) + ".example.com", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateGivenName(tc.givenName, tc.baseDomain)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateGivenName(%q, %q) error = %v, wantErr %v",
					tc.givenName, tc.baseDomain, err, tc.wantErr)
			}
		})
	}
}

func TestPeerChangeFromMapRequest(t *testing.T) {
	nKeys := []key.NodePublic{
		key.NewNode().Public(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	}

	dKeys := []key.DiscoPublic{
		key.NewDisco().Public(),
		key.NewDisco().Public(),
		key.NewDisco().Public(),
	}

	tests := []struct {
		name   string
		node   Node
		mapReq tailcfg.MapRequest
		want   tailcfg.PeerChange
	}{
		{
			name: "preferred-derp-changed",
			node: Node{
				ID:        1,
				NodeKey:   nKeys[0],
				DiscoKey:  dKeys[0],
				Endpoints: []netip.AddrPort{},
				Hostinfo: &tailcfg.Hostinfo{
					NetInfo: &tailcfg.NetInfo{
						PreferredDERP: 998,
					},
				},
			},
			mapReq: tailcfg.MapRequest{
				NodeKey:  nKeys[0],
				DiscoKey: dKeys[0],
				Hostinfo: &tailcfg.Hostinfo{
					NetInfo: &tailcfg.NetInfo{
						PreferredDERP: 999,
					},
				},
			},
			want: tailcfg.PeerChange{
				NodeID:     1,
				DERPRegion: 999,
			},
		},
		{
			name: "preferred-derp-no-changed",
			node: Node{
				ID:        1,
				NodeKey:   nKeys[0],
				DiscoKey:  dKeys[0],
				Endpoints: []netip.AddrPort{},
				Hostinfo: &tailcfg.Hostinfo{
					NetInfo: &tailcfg.NetInfo{
						PreferredDERP: 100,
					},
				},
			},
			mapReq: tailcfg.MapRequest{
				NodeKey:  nKeys[0],
				DiscoKey: dKeys[0],
				Hostinfo: &tailcfg.Hostinfo{
					NetInfo: &tailcfg.NetInfo{
						PreferredDERP: 100,
					},
				},
			},
			want: tailcfg.PeerChange{
				NodeID:     1,
				DERPRegion: 0,
			},
		},
		{
			name: "preferred-derp-no-mapreq-netinfo",
			node: Node{
				ID:        1,
				NodeKey:   nKeys[0],
				DiscoKey:  dKeys[0],
				Endpoints: []netip.AddrPort{},
				Hostinfo: &tailcfg.Hostinfo{
					NetInfo: &tailcfg.NetInfo{
						PreferredDERP: 200,
					},
				},
			},
			mapReq: tailcfg.MapRequest{
				NodeKey:  nKeys[0],
				DiscoKey: dKeys[0],
				Hostinfo: &tailcfg.Hostinfo{},
			},
			want: tailcfg.PeerChange{
				NodeID:     1,
				DERPRegion: 0,
			},
		},
		{
			name: "preferred-derp-no-node-netinfo",
			node: Node{
				ID:        1,
				NodeKey:   nKeys[0],
				DiscoKey:  dKeys[0],
				Endpoints: []netip.AddrPort{},
				Hostinfo:  &tailcfg.Hostinfo{},
			},
			mapReq: tailcfg.MapRequest{
				NodeKey:  nKeys[0],
				DiscoKey: dKeys[0],
				Hostinfo: &tailcfg.Hostinfo{
					NetInfo: &tailcfg.NetInfo{
						PreferredDERP: 200,
					},
				},
			},
			want: tailcfg.PeerChange{
				NodeID:     1,
				DERPRegion: 200,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.node.PeerChangeFromMapRequest(tc.mapReq)

			if diff := cmp.Diff(tc.want, got, cmpopts.IgnoreFields(tailcfg.PeerChange{}, "LastSeen")); diff != "" {
				t.Errorf("Patch unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestApplyPeerChange(t *testing.T) {
	tests := []struct {
		name       string
		nodeBefore Node
		change     *tailcfg.PeerChange
		want       Node
	}{
		{
			name:       "hostinfo-and-netinfo-not-exists",
			nodeBefore: Node{},
			change: &tailcfg.PeerChange{
				DERPRegion: 1,
			},
			want: Node{
				Hostinfo: &tailcfg.Hostinfo{
					NetInfo: &tailcfg.NetInfo{
						PreferredDERP: 1,
					},
				},
			},
		},
		{
			name: "hostinfo-netinfo-not-exists",
			nodeBefore: Node{
				Hostinfo: &tailcfg.Hostinfo{
					Hostname: "test",
				},
			},
			change: &tailcfg.PeerChange{
				DERPRegion: 3,
			},
			want: Node{
				Hostinfo: &tailcfg.Hostinfo{
					Hostname: "test",
					NetInfo: &tailcfg.NetInfo{
						PreferredDERP: 3,
					},
				},
			},
		},
		{
			name: "hostinfo-netinfo-exists-derp-set",
			nodeBefore: Node{
				Hostinfo: &tailcfg.Hostinfo{
					Hostname: "test",
					NetInfo: &tailcfg.NetInfo{
						PreferredDERP: 999,
					},
				},
			},
			change: &tailcfg.PeerChange{
				DERPRegion: 2,
			},
			want: Node{
				Hostinfo: &tailcfg.Hostinfo{
					Hostname: "test",
					NetInfo: &tailcfg.NetInfo{
						PreferredDERP: 2,
					},
				},
			},
		},
		{
			name:       "endpoints-not-set",
			nodeBefore: Node{},
			change: &tailcfg.PeerChange{
				Endpoints: []netip.AddrPort{
					netip.MustParseAddrPort("8.8.8.8:88"),
				},
			},
			want: Node{
				Endpoints: []netip.AddrPort{
					netip.MustParseAddrPort("8.8.8.8:88"),
				},
			},
		},
		{
			name: "endpoints-set",
			nodeBefore: Node{
				Endpoints: []netip.AddrPort{
					netip.MustParseAddrPort("6.6.6.6:66"),
				},
			},
			change: &tailcfg.PeerChange{
				Endpoints: []netip.AddrPort{
					netip.MustParseAddrPort("8.8.8.8:88"),
				},
			},
			want: Node{
				Endpoints: []netip.AddrPort{
					netip.MustParseAddrPort("8.8.8.8:88"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.nodeBefore.ApplyPeerChange(tt.change)

			if diff := cmp.Diff(tt.want, tt.nodeBefore, util.Comparers...); diff != "" {
				t.Errorf("Patch unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNodeRegisterMethodToV1Enum(t *testing.T) {
	tests := []struct {
		name string
		node Node
		want v1.RegisterMethod
	}{
		{
			name: "authkey",
			node: Node{
				ID:             1,
				RegisterMethod: util.RegisterMethodAuthKey,
			},
			want: v1.RegisterMethod_REGISTER_METHOD_AUTH_KEY,
		},
		{
			name: "oidc",
			node: Node{
				ID:             1,
				RegisterMethod: util.RegisterMethodOIDC,
			},
			want: v1.RegisterMethod_REGISTER_METHOD_OIDC,
		},
		{
			name: "cli",
			node: Node{
				ID:             1,
				RegisterMethod: util.RegisterMethodCLI,
			},
			want: v1.RegisterMethod_REGISTER_METHOD_CLI,
		},
		{
			name: "unknown",
			node: Node{
				ID: 0,
			},
			want: v1.RegisterMethod_REGISTER_METHOD_UNSPECIFIED,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.node.RegisterMethodToV1Enum()

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("RegisterMethodToV1Enum() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

// TestHasNetworkChanges tests the [NodeView] method for detecting
// when a node's network properties have changed.
func TestHasNetworkChanges(t *testing.T) {
	mustIPPtr := func(s string) *netip.Addr {
		ip := netip.MustParseAddr(s)
		return &ip
	}

	tests := []struct {
		name    string
		old     *Node
		new     *Node
		changed bool
	}{
		{
			name: "no changes",
			old: &Node{
				ID:             1,
				IPv4:           mustIPPtr("100.64.0.1"),
				IPv6:           mustIPPtr("fd7a:115c:a1e0::1"),
				Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}},
				ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")},
			},
			new: &Node{
				ID:             1,
				IPv4:           mustIPPtr("100.64.0.1"),
				IPv6:           mustIPPtr("fd7a:115c:a1e0::1"),
				Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}},
				ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")},
			},
			changed: false,
		},
		{
			name: "IPv4 changed",
			old: &Node{
				ID:   1,
				IPv4: mustIPPtr("100.64.0.1"),
				IPv6: mustIPPtr("fd7a:115c:a1e0::1"),
			},
			new: &Node{
				ID:   1,
				IPv4: mustIPPtr("100.64.0.2"),
				IPv6: mustIPPtr("fd7a:115c:a1e0::1"),
			},
			changed: true,
		},
		{
			name: "IPv6 changed",
			old: &Node{
				ID:   1,
				IPv4: mustIPPtr("100.64.0.1"),
				IPv6: mustIPPtr("fd7a:115c:a1e0::1"),
			},
			new: &Node{
				ID:   1,
				IPv4: mustIPPtr("100.64.0.1"),
				IPv6: mustIPPtr("fd7a:115c:a1e0::2"),
			},
			changed: true,
		},
		{
			name: "RoutableIPs added",
			old: &Node{
				ID:       1,
				IPv4:     mustIPPtr("100.64.0.1"),
				Hostinfo: &tailcfg.Hostinfo{},
			},
			new: &Node{
				ID:       1,
				IPv4:     mustIPPtr("100.64.0.1"),
				Hostinfo: &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}},
			},
			changed: true,
		},
		{
			name: "RoutableIPs removed",
			old: &Node{
				ID:       1,
				IPv4:     mustIPPtr("100.64.0.1"),
				Hostinfo: &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}},
			},
			new: &Node{
				ID:       1,
				IPv4:     mustIPPtr("100.64.0.1"),
				Hostinfo: &tailcfg.Hostinfo{},
			},
			changed: true,
		},
		{
			name: "RoutableIPs changed",
			old: &Node{
				ID:       1,
				IPv4:     mustIPPtr("100.64.0.1"),
				Hostinfo: &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}},
			},
			new: &Node{
				ID:       1,
				IPv4:     mustIPPtr("100.64.0.1"),
				Hostinfo: &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")}},
			},
			changed: true,
		},
		{
			name: "SubnetRoutes added",
			old: &Node{
				ID:             1,
				IPv4:           mustIPPtr("100.64.0.1"),
				Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")}},
				ApprovedRoutes: []netip.Prefix{},
			},
			new: &Node{
				ID:             1,
				IPv4:           mustIPPtr("100.64.0.1"),
				Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")}},
				ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")},
			},
			changed: true,
		},
		{
			name: "SubnetRoutes removed",
			old: &Node{
				ID:             1,
				IPv4:           mustIPPtr("100.64.0.1"),
				Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")}},
				ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")},
			},
			new: &Node{
				ID:             1,
				IPv4:           mustIPPtr("100.64.0.1"),
				Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")}},
				ApprovedRoutes: []netip.Prefix{},
			},
			changed: true,
		},
		{
			name: "SubnetRoutes changed",
			old: &Node{
				ID:             1,
				IPv4:           mustIPPtr("100.64.0.1"),
				Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("192.168.0.0/24")}},
				ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
			},
			new: &Node{
				ID:             1,
				IPv4:           mustIPPtr("100.64.0.1"),
				Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("192.168.0.0/24")}},
				ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")},
			},
			changed: true,
		},
		{
			name: "irrelevant property changed (Hostname)",
			old: &Node{
				ID:       1,
				IPv4:     mustIPPtr("100.64.0.1"),
				Hostname: "old-name",
			},
			new: &Node{
				ID:       1,
				IPv4:     mustIPPtr("100.64.0.1"),
				Hostname: "new-name",
			},
			changed: false,
		},
		{
			name: "ExitRoutes approved",
			old: &Node{
				ID:       1,
				IPv4:     mustIPPtr("100.64.0.1"),
				Hostinfo: &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}},
			},
			new: &Node{
				ID:             1,
				IPv4:           mustIPPtr("100.64.0.1"),
				Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}},
				ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
			},
			changed: true,
		},
		{
			name: "ExitRoutes unchanged when SubnetRoutes change",
			old: &Node{
				ID:             1,
				IPv4:           mustIPPtr("100.64.0.1"),
				Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"), netip.MustParsePrefix("10.0.0.0/24")}},
				ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
			},
			new: &Node{
				ID:             1,
				IPv4:           mustIPPtr("100.64.0.1"),
				Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"), netip.MustParsePrefix("10.0.0.0/24")}},
				ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"), netip.MustParsePrefix("10.0.0.0/24")},
			},
			changed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.new.View().HasNetworkChanges(tt.old.View())
			if got != tt.changed {
				t.Errorf("HasNetworkChanges() = %v, want %v", got, tt.changed)
			}
		})
	}
}

func policyChangeTestNode() Node {
	ipv4 := netip.MustParseAddr("100.64.0.1")
	now := time.Now()

	return Node{
		ID:         1,
		MachineKey: key.NewMachine().Public(),
		NodeKey:    key.NewNode().Public(),
		DiscoKey:   key.NewDisco().Public(),
		Hostname:   "node",
		GivenName:  "node",
		IPv4:       &ipv4,
		CreatedAt:  now,
		UpdatedAt:  now,
		Hostinfo:   &tailcfg.Hostinfo{Hostname: "node"},
	}
}

// TestHasPolicyChangeUserIDPointerIdentity ensures two distinct *uint
// values holding the same user ID do not register as a policy change.
func TestHasPolicyChangeUserIDPointerIdentity(t *testing.T) {
	userID := uint(7)

	a := policyChangeTestNode()
	a.UserID = &userID

	b := policyChangeTestNode()
	otherPtr := new(uint)
	*otherPtr = 7
	b.UserID = otherPtr

	// Different pointers, same value.
	require.NotSame(t, a.UserID, b.UserID)
	require.False(t, a.View().HasPolicyChange(b.View()),
		"same UserID value via distinct pointers must not register as policy change")

	// And a real change must register.
	c := policyChangeTestNode()
	otherVal := uint(8)
	c.UserID = &otherVal
	require.True(t, a.View().HasPolicyChange(c.View()),
		"different UserID value must register as policy change")
}

// TestHasPolicyChangeUserIDValidity covers the nil vs non-nil transition.
func TestHasPolicyChangeUserIDValidity(t *testing.T) {
	a := policyChangeTestNode()
	// a.UserID nil
	b := policyChangeTestNode()
	v := uint(1)
	b.UserID = &v

	require.True(t, a.View().HasPolicyChange(b.View()),
		"nil -> non-nil UserID must register as policy change")
}

// TestHasPolicyChangeExitRoutes covers the missing ExitRoutes comparison.
func TestHasPolicyChangeExitRoutes(t *testing.T) {
	exitV4 := netip.MustParsePrefix("0.0.0.0/0")
	exitV6 := netip.MustParsePrefix("::/0")

	base := policyChangeTestNode()
	base.Hostinfo.RoutableIPs = []netip.Prefix{exitV4, exitV6}
	base.ApprovedRoutes = nil // not approved -> no exit routes

	b := policyChangeTestNode()
	b.Hostinfo.RoutableIPs = []netip.Prefix{exitV4, exitV6}
	b.ApprovedRoutes = []netip.Prefix{exitV4, exitV6} // approved -> exit routes live

	require.True(t, base.View().HasPolicyChange(b.View()),
		"enabling exit routes must register as policy change")

	// Reverse: approved on both, no change.
	c := policyChangeTestNode()
	c.Hostinfo.RoutableIPs = []netip.Prefix{exitV4, exitV6}
	c.ApprovedRoutes = []netip.Prefix{exitV4, exitV6}

	require.False(t, b.View().HasPolicyChange(c.View()),
		"identical exit-route state must not register as policy change")
}

func TestHasPolicyChangeFields(t *testing.T) {
	subnet := netip.MustParsePrefix("10.0.0.0/24")
	exit := netip.MustParsePrefix("0.0.0.0/0")

	tests := []struct {
		name   string
		mutate func(*Node)
		want   bool
	}{
		{name: "no change", mutate: func(*Node) {}, want: false},
		{name: "last seen", mutate: func(n *Node) { n.LastSeen = new(time.Now()) }, want: false},
		{name: "expiry", mutate: func(n *Node) { n.Expiry = new(time.Now()) }, want: false},
		{name: "hostname", mutate: func(n *Node) { n.Hostname = "other" }, want: false},
		{name: "tags", mutate: func(n *Node) { n.Tags = []string{"tag:x"} }, want: true},
		{
			name: "ipv4",
			mutate: func(n *Node) {
				ip := netip.MustParseAddr("100.64.0.2")
				n.IPv4 = &ip
			},
			want: true,
		},
		{
			name:   "announced but unapproved subnet",
			mutate: func(n *Node) { n.Hostinfo.RoutableIPs = []netip.Prefix{subnet} },
			want:   false,
		},
		{
			name: "approved and announced subnet",
			mutate: func(n *Node) {
				n.Hostinfo.RoutableIPs = []netip.Prefix{subnet}
				n.ApprovedRoutes = []netip.Prefix{subnet}
			},
			want: true,
		},
		{
			name: "approved and announced exit",
			mutate: func(n *Node) {
				n.Hostinfo.RoutableIPs = []netip.Prefix{exit}
				n.ApprovedRoutes = []netip.Prefix{exit}
			},
			want: true,
		},
		{
			name:   "user association cleared",
			mutate: func(n *Node) { n.User = nil },
			want:   true,
		},
		{
			name:   "user association moved",
			mutate: func(n *Node) { n.User = &User{Model: gorm.Model{ID: 8}} },
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userID := uint(7)

			base := policyChangeTestNode()
			base.UserID = &userID
			base.User = &User{Model: gorm.Model{ID: userID}}

			other := *base.Clone()
			tt.mutate(&other)

			require.Equal(t, tt.want, other.View().HasPolicyChange(base.View()))
		})
	}
}

func TestNodeIsExpiredAt(t *testing.T) {
	now := time.Now()
	zero := time.Time{}
	justBefore := now.Add(-time.Nanosecond)

	tests := []struct {
		name   string
		expiry *time.Time
		want   bool
	}{
		{name: "nil expiry", expiry: nil, want: false},
		{name: "zero expiry", expiry: &zero, want: false},
		{name: "expiry equals now", expiry: &now, want: false},
		{name: "now one nanosecond after expiry", expiry: &justBefore, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &Node{Expiry: tt.expiry}
			require.Equal(t, tt.want, n.IsExpiredAt(now))
			require.Equal(t, tt.want, n.View().IsExpiredAt(now))
		})
	}

	t.Run("invalid view", func(t *testing.T) {
		require.True(t, NodeView{}.IsExpiredAt(now),
			"an invalid view counts as expired, like IsExpired")
	})
}

func TestValidateHostinfo(t *testing.T) {
	t.Parallel()

	routes := make([]netip.Prefix, MaxRoutableIPs)
	for i := range routes {
		routes[i] = netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfd, byte(i >> 8), byte(i)}), 64)
	}

	latencies := make(map[string]float64, 300)
	for i := range 300 {
		latencies[fmt.Sprintf("%d-v4", i)] = 0.01
	}

	base, err := json.Marshal(&tailcfg.Hostinfo{OSVersion: "x"})
	require.NoError(t, err)

	exact := strings.Repeat("x", MaxHostinfoSize-len(base)+1)

	for _, tt := range []struct {
		name     string
		hostinfo *tailcfg.Hostinfo
		wantErr  bool
	}{
		{name: "nil"},
		{name: "hostname at limit", hostinfo: &tailcfg.Hostinfo{Hostname: strings.Repeat("h", 255)}},
		{name: "hostname over limit", hostinfo: &tailcfg.Hostinfo{Hostname: strings.Repeat("h", 256)}, wantErr: true},
		{name: "hostname bytes", hostinfo: &tailcfg.Hostinfo{Hostname: strings.Repeat("é", 128)}, wantErr: true},
		{name: "routes at limit", hostinfo: &tailcfg.Hostinfo{RoutableIPs: routes}},
		{name: "routes over limit", hostinfo: &tailcfg.Hostinfo{RoutableIPs: append(slices.Clone(routes), routes[0])}, wantErr: true},
		{name: "tags at limit", hostinfo: &tailcfg.Hostinfo{RequestTags: make([]string, 256)}},
		{name: "tags over limit", hostinfo: &tailcfg.Hostinfo{RequestTags: make([]string, 257)}, wantErr: true},
		{name: "metadata at byte limit", hostinfo: &tailcfg.Hostinfo{OSVersion: exact}},
		{name: "metadata over byte limit", hostinfo: &tailcfg.Hostinfo{OSVersion: exact + "x"}, wantErr: true},
		{name: "NetInfo over byte limit", hostinfo: &tailcfg.Hostinfo{NetInfo: &tailcfg.NetInfo{LinkType: strings.Repeat("n", MaxHostinfoSize)}}, wantErr: true},
		{name: "budgets compose", hostinfo: &tailcfg.Hostinfo{OSVersion: strings.Repeat("o", 60<<10), NetInfo: &tailcfg.NetInfo{LinkType: strings.Repeat("n", 60<<10)}}},
		{name: "small entries need no field-specific truncation", hostinfo: &tailcfg.Hostinfo{
			Services:     make([]tailcfg.Service, 300),
			WoLMACs:      make([]string, 300),
			SSH_HostKeys: make([]string, 300),
			NetInfo:      &tailcfg.NetInfo{DERPLatency: latencies},
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			want := tt.hostinfo.Clone()

			err := ValidateHostinfo(tt.hostinfo)
			if tt.wantErr {
				require.ErrorIs(t, err, ErrHostinfoTooLarge)
			} else {
				require.NoError(t, err)
			}

			require.True(t, want.Equal(tt.hostinfo), "validation must not change the report")
		})
	}
}

func TestSanitizeHostinfo(t *testing.T) {
	t.Parallel()

	require.Nil(t, SanitizeHostinfo(nil))

	loc := &tailcfg.Location{
		Country:     "Norway",
		CountryCode: "NO",
		City:        "Oslo",
		CityCode:    "OSL",
		Latitude:    59.91,
		Longitude:   10.75,
	}

	full := &tailcfg.Hostinfo{
		IPNVersion:      "1.58.2",
		FrontendLogID:   "front123",
		BackendLogID:    "back123",
		OS:              "linux",
		OSVersion:       "6.12.0",
		Container:       opt.Bool("true"),
		Env:             "kn",
		Distro:          "debian",
		DistroVersion:   "12",
		DistroCodeName:  "bookworm",
		App:             "test-app",
		Desktop:         opt.Bool("false"),
		Package:         "deb",
		DeviceModel:     "server",
		PushDeviceToken: "token123",
		Hostname:        "my-host",
		ShieldsUp:       true,
		ShareeNode:      true,
		NoLogsNoSupport: true,
		RemoteConfig:    true,
		WireIngress:     true,
		IngressEnabled:  true,
		AllowsUpdate:    true,
		Machine:         "x86_64",
		GoArch:          "amd64",
		GoArchVar:       "v3",
		GoVersion:       "go1.27.3",
		RoutableIPs:     []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		RequestTags:     []string{"tag:server"},
		WoLMACs:         []string{"00:11:22:33:44:55"},
		Services:        []tailcfg.Service{{Proto: tailcfg.PeerAPI4, Port: 4242}},
		NetInfo: &tailcfg.NetInfo{
			MappingVariesByDestIP: opt.Bool("true"),
			WorkingIPv6:           opt.Bool("true"),
			OSHasIPv6:             opt.Bool("true"),
			WorkingUDP:            opt.Bool("true"),
			WorkingICMPv4:         opt.Bool("true"),
			HavePortMap:           true,
			UPnP:                  opt.Bool("true"),
			PMP:                   opt.Bool("true"),
			PCP:                   opt.Bool("true"),
			PreferredDERP:         2,
			LinkType:              "wired",
			DERPLatency:           map[string]float64{"1-v4": 0.05},
			FirewallMode:          "nft-forced",
		},
		SSH_HostKeys:    []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..."},
		Cloud:           "gcp",
		Userspace:       opt.Bool("false"),
		UserspaceRouter: opt.Bool("false"),
		AppConnector:    opt.Bool("true"),
		ServicesHash:    "hash123",
		PeerRelay:       true,
		ExitNodeID:      tailcfg.StableNodeID("123"),
		Location:        loc,
	}

	sanitized := SanitizeHostinfo(full)
	require.NotNil(t, sanitized)

	// Operational fields MUST be retained:
	assert.Equal(t, "my-host", sanitized.Hostname)
	assert.Equal(t, "linux", sanitized.OS)
	assert.Equal(t, []string{"tag:server"}, sanitized.RequestTags)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}, sanitized.RoutableIPs)
	assert.Equal(t, []tailcfg.Service{{Proto: tailcfg.PeerAPI4, Port: 4242}}, sanitized.Services)
	assert.Equal(t, []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..."}, sanitized.SSH_HostKeys)
	assert.Equal(t, opt.Bool("true"), sanitized.AppConnector)
	require.NotNil(t, sanitized.Location)
	assert.Equal(t, loc, sanitized.Location)
	require.NotNil(t, sanitized.NetInfo)
	assert.Equal(t, tailcfg.DERPRegionID(2), sanitized.NetInfo.PreferredDERP)

	// Fingerprinting and telemetry fields MUST be stripped:
	assert.Empty(t, sanitized.IPNVersion)
	assert.Empty(t, sanitized.FrontendLogID)
	assert.Empty(t, sanitized.BackendLogID)
	assert.Empty(t, sanitized.OSVersion)
	assert.Empty(t, sanitized.Container)
	assert.Empty(t, sanitized.Env)
	assert.Empty(t, sanitized.Distro)
	assert.Empty(t, sanitized.DistroVersion)
	assert.Empty(t, sanitized.DistroCodeName)
	assert.Empty(t, sanitized.App)
	assert.Empty(t, sanitized.Desktop)
	assert.Empty(t, sanitized.Package)
	assert.Empty(t, sanitized.DeviceModel)
	assert.Empty(t, sanitized.PushDeviceToken)
	assert.False(t, sanitized.ShieldsUp)
	assert.False(t, sanitized.ShareeNode)
	assert.False(t, sanitized.NoLogsNoSupport)
	assert.False(t, sanitized.RemoteConfig)
	assert.False(t, sanitized.WireIngress)
	assert.False(t, sanitized.IngressEnabled)
	assert.False(t, sanitized.AllowsUpdate)
	assert.Empty(t, sanitized.Machine)
	assert.Empty(t, sanitized.GoArch)
	assert.Empty(t, sanitized.GoArchVar)
	assert.Empty(t, sanitized.GoVersion)
	assert.Empty(t, sanitized.WoLMACs)
	assert.Empty(t, sanitized.Cloud)
	assert.Empty(t, sanitized.Userspace)
	assert.Empty(t, sanitized.UserspaceRouter)
	assert.Empty(t, sanitized.ServicesHash)
	assert.False(t, sanitized.PeerRelay)
	assert.Empty(t, sanitized.ExitNodeID)

	// NetInfo diagnostics MUST be stripped:
	assert.Empty(t, sanitized.NetInfo.MappingVariesByDestIP)
	assert.Empty(t, sanitized.NetInfo.WorkingIPv6)
	assert.Empty(t, sanitized.NetInfo.OSHasIPv6)
	assert.Empty(t, sanitized.NetInfo.WorkingUDP)
	assert.Empty(t, sanitized.NetInfo.WorkingICMPv4)
	assert.False(t, sanitized.NetInfo.HavePortMap)
	assert.Empty(t, sanitized.NetInfo.UPnP)
	assert.Empty(t, sanitized.NetInfo.PMP)
	assert.Empty(t, sanitized.NetInfo.PCP)
	assert.Empty(t, sanitized.NetInfo.LinkType)
	assert.Nil(t, sanitized.NetInfo.DERPLatency)
	assert.Empty(t, sanitized.NetInfo.FirewallMode)

	// Slices and pointers must be cloned independently:
	sanitized.RequestTags[0] = "mutated"
	assert.Equal(t, "tag:server", full.RequestTags[0])
	sanitized.RoutableIPs[0] = netip.MustParsePrefix("192.168.1.0/24")
	assert.Equal(t, netip.MustParsePrefix("10.0.0.0/24"), full.RoutableIPs[0])
	sanitized.Location.City = "Bergen"
	assert.Equal(t, "Oslo", full.Location.City)

	// NetInfo nil handling
	hiNoNetInfo := &tailcfg.Hostinfo{Hostname: "host2"}
	assert.Nil(t, SanitizeHostinfo(hiNoNetInfo).NetInfo)
}
