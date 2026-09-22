package table

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestToGlobalPathLocalKeyCarriesRD pins the ownership identity: after a local
// VRF path is promoted to VPNv4, its destination key MUST include the VRF RD.
// Two VRFs exporting the same IPv4 prefix must produce distinct keys;
// otherwise message coalescing and RIB-out bookkeeping alias the paths across
// tenants.
func TestToGlobalPathLocalKeyCarriesRD(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_RTC_UC}, oc.RouteSelectionOptionsConfig{}, oc.UseMultiplePathsConfig{})
	pi := createPeerInfo(64511, "127.0.0.11")
	vrfA := addVrf(t, tm, pi, "vrfA", "111:100", []string{"111:100"}, []string{"111:100"}, 1)
	vrfB := addVrf(t, tm, pi, "vrfB", "111:200", []string{"111:200"}, []string{"111:200"}, 2)

	prefix, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	require.NoError(t, err)
	pan, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("8.8.8.8"))
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), pan}

	newUC := func() *Path {
		return NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: prefix}, false, attrs, time.Now(), false)
	}
	pA := newUC()
	pB := newUC()
	require.NoError(t, vrfA.ToGlobalPath(pA))
	require.NoError(t, vrfB.ToGlobalPath(pB))

	assert.NotEqual(t, pA.GetDestLocalKey(), pB.GetDestLocalKey(),
		"shared IPv4 prefix across VRFs must yield RD-distinct destination keys")
	assert.Contains(t, pA.GetDestLocalKey().Prefix, "111:100")
	assert.Contains(t, pB.GetDestLocalKey().Prefix, "111:200")
	assert.Equal(t, bgp.RF_IPv4_VPN, pA.GetFamily())
	assert.Equal(t, pA.GetNlri().String(), pA.GetDestLocalKey().Prefix)
}

// TestDeleteVrfConcurrentUpdates repeatedly deletes while unrelated VRF paths
// churn; once the target VRF is deleted, its RT index entry and VPN paths must
// stay empty, and the surviving VRF must remain fully populated.
func TestDeleteVrfConcurrentUpdates(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_VPN, bgp.RF_RTC_UC}, oc.RouteSelectionOptionsConfig{}, oc.UseMultiplePathsConfig{})
	pi := createPeerInfo(64511, "127.0.0.11")
	addVrf(t, tm, pi, "vrfA", "111:100", []string{"111:100"}, []string{"111:100"}, 1)
	addVrf(t, tm, pi, "vrfB", "111:200", []string{"111:200"}, []string{"111:200"}, 2)

	install := func(rd string, octet byte, rt string) {
		p := makeVpn4Path(t, nil, fmt.Sprintf("10.20.%d.0", octet), "8.8.8.8", rd, []string{rt})
		tm.Update(p)
	}
	install("111:100", 1, "111:100")
	install("111:200", 2, "111:200")

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Churn B paths concurrently; each round uses a fresh prefix.
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := byte(100)
		for {
			select {
			case <-stop:
				return
			default:
			}
			install("111:200", i, "111:200")
			i++
			time.Sleep(time.Millisecond)
		}
	}()

	// Concurrent duplicate deletes: first wins, the rest error.
	var firstDone sync.WaitGroup
	firstDone.Add(1)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			firstDone.Wait()
			_, _ = tm.DeleteVrf("vrfA")
		}()
	}
	msgs, err := tm.DeleteVrf("vrfA")
	require.NoError(t, err)
	firstDone.Done()
	for _, m := range msgs {
		tm.Update(m)
	}

	close(stop)
	wg.Wait()

	// Retrying the delete must keep erroring and must never resurrect A state.
	_, err = tm.DeleteVrf("vrfA")
	assert.Error(t, err)

	_, rtA, _ := parseRDRT("111:100")
	_, rtB, _ := parseRDRT("111:200")
	assert.Nil(t, tm.GetPathsByRT(rtA, []bgp.Family{bgp.RF_IPv4_VPN}), "deleted VRF index entry must stay empty")
	bPaths := tm.GetPathsByRT(rtB, []bgp.Family{bgp.RF_IPv4_VPN})
	for _, p := range bPaths {
		assert.Equal(t, "111:200", p.GetNlri().(*bgp.LabeledVPNIPAddrPrefix).RD.String())
	}
	assert.NotEmpty(t, bPaths, "surviving VRF keeps its own paths")
}
