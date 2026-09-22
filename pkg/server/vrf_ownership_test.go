package server

import (
	"context"
	"net/netip"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func addLocalVrfRoute(t *testing.T, s *BgpServer, vrfID, prefixStr string, exportRTs []string) {
	t.Helper()
	panh, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("0.0.0.0"))
	rts := make([]bgp.ExtendedCommunityInterface, 0, len(exportRTs))
	for _, rtStr := range exportRTs {
		_, rt, err := parseRDRT(rtStr)
		require.NoError(t, err)
		rts = append(rts, rt)
	}
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		panh,
		bgp.NewPathAttributeExtendedCommunities(rts),
	}
	prefix, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefixStr))
	require.NoError(t, err)
	p, err := apiutil.NewPath(bgp.RF_IPv4_UC, prefix, false, attrs, time.Now())
	require.NoError(t, err)
	_, err = s.AddPath(apiutil.AddPathRequest{VRFID: vrfID, Paths: []*apiutil.Path{mustApi2apiutilPath(p)}})
	require.NoError(t, err)
}

func vpnPaths(s *BgpServer) []*table.Path {
	return s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_VPN})
}

// TestDeleteVrfRebuildOwnership drives the full delete -> rebuild sequence and
// inspects every state plane: the VPNv4 RIB, the RT index, the RTC table and
// a recreated same-name VRF.
func TestDeleteVrfRebuildOwnership(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", 10181)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	addVrf(t, s, "vrfA", "111:100", []string{"111:100"}, []string{"111:100"}, 1)
	addVrf(t, s, "vrfB", "111:200", []string{"111:200"}, []string{"111:200"}, 2)

	addLocalVrfRoute(t, s, "vrfA", "10.10.10.0/24", []string{"111:100"})
	addLocalVrfRoute(t, s, "vrfB", "10.10.10.0/24", []string{"111:200"})

	require.Eventually(t, func() bool { return len(vpnPaths(s)) == 2 }, 3*time.Second, 10*time.Millisecond)

	_, rtA, err := parseRDRT("111:100")
	require.NoError(t, err)
	_, rtB, err := parseRDRT("111:200")
	require.NoError(t, err)
	assert.Len(t, s.globalRib.GetPathsByRT(rtA, []bgp.Family{bgp.RF_IPv4_VPN}), 1)
	assert.Len(t, s.globalRib.GetPathsByRT(rtB, []bgp.Family{bgp.RF_IPv4_VPN}), 1)

	require.NoError(t, s.DeleteVrf(context.Background(), &api.DeleteVrfRequest{Name: "vrfA"}))

	// VPNv4 RIB: only vrfB's path may survive.
	var got []*table.Path
	require.Eventually(t, func() bool {
		got = vpnPaths(s)
		return len(got) == 1
	}, 3*time.Second, 10*time.Millisecond)
	for _, p := range got {
		nlri := p.GetNlri().(*bgp.LabeledVPNIPAddrPrefix)
		assert.Equal(t, "111:200", nlri.RD.String())
	}

	// RT index: A must be gone, B must remain.
	assert.Nil(t, s.globalRib.GetPathsByRT(rtA, []bgp.Family{bgp.RF_IPv4_VPN}))
	assert.Len(t, s.globalRib.GetPathsByRT(rtB, []bgp.Family{bgp.RF_IPv4_VPN}), 1)

	// RTC table: A's membership gone, B's remains.
	rtcPaths := s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_RTC_UC})
	for _, p := range rtcPaths {
		nlri := p.GetNlri().(*bgp.RouteTargetMembershipNLRI)
		assert.NotEqual(t, "111:100", nlri.RouteTarget.String())
	}

	// Duplicate delete: error, but B state untouched.
	err = s.DeleteVrf(context.Background(), &api.DeleteVrfRequest{Name: "vrfA"})
	assert.Error(t, err)
	assert.Len(t, vpnPaths(s), 1)
	assert.Len(t, s.globalRib.GetPathsByRT(rtB, []bgp.Family{bgp.RF_IPv4_VPN}), 1)

	// Recreate same-name VRF: it must not reattach to old state.
	addVrf(t, s, "vrfA", "111:100", []string{"111:100"}, []string{"111:100"}, 1)
	assert.Nil(t, s.globalRib.GetPathsByRT(rtA, []bgp.Family{bgp.RF_IPv4_VPN}), "recreated VRF must not resurrect old tenant paths")
	assert.Len(t, vpnPaths(s), 1)

	// Adding a fresh route must yield exactly one path for A again.
	addLocalVrfRoute(t, s, "vrfA", "10.20.20.0/24", []string{"111:100"})
	require.Eventually(t, func() bool { return len(vpnPaths(s)) == 2 }, 3*time.Second, 10*time.Millisecond)
	assert.Len(t, s.globalRib.GetPathsByRT(rtA, []bgp.Family{bgp.RF_IPv4_VPN}), 1)
}
