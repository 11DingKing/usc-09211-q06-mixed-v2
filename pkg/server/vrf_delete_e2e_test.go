package server

import (
	"context"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sharedPrefix = "10.10.10.0/24"

// TestDeleteVrfRebuildE2E drives delete -> recreate between two BGP speakers
// with TWO VRFs exporting the SAME IPv4 prefix under different RDs/RTs.
// Ownership (RD) must be preserved end to end, both with and without RTC.
func TestDeleteVrfRebuildE2E(t *testing.T) {
	cases := []struct {
		name     string
		families []oc.AfiSafiType
	}{
		{"noRTC", []oc.AfiSafiType{oc.AFI_SAFI_TYPE_L3VPN_IPV4_UNICAST}},
		{"rtc", []oc.AfiSafiType{oc.AFI_SAFI_TYPE_L3VPN_IPV4_UNICAST, oc.AFI_SAFI_TYPE_RTC}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runDeleteVrfRebuildE2E(t, tc.families)
		})
	}
}

func runDeleteVrfRebuildE2E(t *testing.T, families []oc.AfiSafiType) {
	ctx := context.Background()
	s1 := runNewServer(t, 1, "1.1.1.1", 10182)
	defer s1.StopBgp(context.Background(), &api.StopBgpRequest{})
	s2 := runNewServer(t, 1, "2.2.2.2", 20182)
	defer s2.StopBgp(context.Background(), &api.StopBgpRequest{})

	addVrf(t, s1, "vrfA", "111:100", []string{"111:100"}, []string{"111:100"}, 1)
	addVrf(t, s1, "vrfB", "111:200", []string{"111:200"}, []string{"111:200"}, 2)
	// Receiver imports BOTH RTs so RTC constrains neither tenant out.
	addVrf(t, s2, "imp", "111:999", []string{"111:100", "111:200"}, []string{"111:999"}, 9)

	if err := peerServers(t, ctx, []*BgpServer{s1, s2}, families); err != nil {
		t.Fatal(err)
	}

	watcher2, err := s2.watch(WatchUpdate(true, "", ""))
	require.NoError(t, err)

	addLocalVrfRoute(t, s1, "vrfA", sharedPrefix, []string{"111:100"})
	addLocalVrfRoute(t, s1, "vrfB", sharedPrefix, []string{"111:200"})

	// Both VRF paths must be advertised even though the IPv4 prefix is identical.
	seen := map[string]bool{} // rd -> advertised
	deadline := time.NewTimer(20 * time.Second)
	for len(seen) < 2 {
		select {
		case ev := <-watcher2.Event():
			if msg, ok := ev.(*watchEventUpdate); ok {
				for _, p := range msg.PathList {
					if vpn, ok := p.GetNlri().(*bgp.LabeledVPNIPAddrPrefix); ok && vpn.Prefix.String() == sharedPrefix {
						seen[vpn.RD.String()] = true
					}
				}
			}
		case <-deadline.C:
			t.Fatalf("timeout waiting for both VPN routes, got %v", seen)
		}
	}
	deadline.Stop()

	// Delete vrfA on the originator.
	require.NoError(t, s1.DeleteVrf(ctx, &api.DeleteVrfRequest{Name: "vrfA"}))

	// s2 must observe exactly one withdraw, for RD 111:100.
	withdraws := map[string]int{}
	advertAfterDel := map[string]int{}
	deadline = time.NewTimer(5 * time.Second)
loop2:
	for {
		select {
		case ev := <-watcher2.Event():
			if msg, ok := ev.(*watchEventUpdate); ok {
				for _, p := range msg.PathList {
					if vpn, ok := p.GetNlri().(*bgp.LabeledVPNIPAddrPrefix); ok && vpn.Prefix.String() == sharedPrefix {
						if p.IsWithdraw {
							withdraws[vpn.RD.String()]++
						} else {
							advertAfterDel[vpn.RD.String()]++
						}
					}
				}
			}
			if withdraws["111:100"] == 1 {
				break loop2
			}
		case <-deadline.C:
			t.Fatalf("timeout waiting for withdraw of RD 111:100, withdraws=%v", withdraws)
		}
	}
	deadline.Stop()
	// Give any stray messages a chance to surface.
	time.Sleep(300 * time.Millisecond)
	assert.Equal(t, 1, withdraws["111:100"], "exactly one withdraw for A")
	assert.Equal(t, 0, withdraws["111:200"], "B must never be withdrawn")
	assert.Equal(t, 0, advertAfterDel["111:100"], "no re-advertisement of A after deletion")

	// Originator state planes.
	assert.Len(t, s1.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_VPN}), 1)
	_, rtA, _ := parseRDRT("111:100")
	_, rtB, _ := parseRDRT("111:200")
	assert.Nil(t, s1.globalRib.GetPathsByRT(rtA, []bgp.Family{bgp.RF_IPv4_VPN}))
	assert.Len(t, s1.globalRib.GetPathsByRT(rtB, []bgp.Family{bgp.RF_IPv4_VPN}), 1)

	// s2's RIB must hold only B.
	got := s2.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_VPN})
	require.Len(t, got, 1)
	assert.Equal(t, "111:200", got[0].GetNlri().(*bgp.LabeledVPNIPAddrPrefix).RD.String())

	// Duplicate delete must error and leave B untouched.
	assert.Error(t, s1.DeleteVrf(ctx, &api.DeleteVrfRequest{Name: "vrfA"}))
	assert.Len(t, s1.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_VPN}), 1)

	// Recreate same-name VRF: it must not reattach to old state.
	addVrf(t, s1, "vrfA", "111:100", []string{"111:100"}, []string{"111:100"}, 1)
	assert.Nil(t, s1.globalRib.GetPathsByRT(rtA, []bgp.Family{bgp.RF_IPv4_VPN}), "recreated VRF must not resurrect old tenant paths")
	assert.Len(t, s1.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_VPN}), 1)

	// Adding a fresh route must yield exactly one advertisement for RD A.
	addLocalVrfRoute(t, s1, "vrfA", sharedPrefix, []string{"111:100"})
	reAdverts := 0
	deadline = time.NewTimer(10 * time.Second)
loop3:
	for {
		select {
		case ev := <-watcher2.Event():
			if msg, ok := ev.(*watchEventUpdate); ok {
				for _, p := range msg.PathList {
					if vpn, ok := p.GetNlri().(*bgp.LabeledVPNIPAddrPrefix); ok &&
						vpn.Prefix.String() == sharedPrefix &&
						vpn.RD.String() == "111:100" && !p.IsWithdraw {
						reAdverts++
						break loop3
					}
				}
			}
		case <-deadline.C:
			t.Fatal("timeout waiting for re-advertisement after VRF rebuild")
		}
	}
	deadline.Stop()
	time.Sleep(300 * time.Millisecond)
	assert.Equal(t, 1, reAdverts, "exactly one advertisement for A after rebuild")

	// Final receiver RIB: two paths, one per RD.
	require.Eventually(t, func() bool {
		return len(s2.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_VPN})) == 2
	}, 5*time.Second, 20*time.Millisecond)
}
