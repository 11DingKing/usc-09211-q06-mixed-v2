package table

import (
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
)

// Repro: DeleteVrf -> feed resulting withdraw clones back into Update like the
// server's propagateUpdate does -> check that the VPN family table and the RT
// index both end up empty.
func TestDeleteVrfWithdrawsVPNRIBAndRTIndex(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_VPN, bgp.RF_RTC_UC}, oc.RouteSelectionOptionsConfig{}, oc.UseMultiplePathsConfig{})
	pi := createPeerInfo(64511, "127.0.0.11")

	vrf := addVrf(t, tm, pi, "vrfA", "111:100", []string{"111:222"}, []string{"111:222"}, 1)

	// A local VPN path owned by vrfA (RD 111:100), carrying export RT 111:222.
	p := makeVpn4Path(t, nil, "10.20.30.0", "8.8.8.8", "111:100", []string{"111:222"})
	// make it local
	p = NewPath(bgp.RF_IPv4_VPN, nil, bgp.PathNLRI{NLRI: p.GetNlri()}, false, p.GetPathAttrs(), time.Now(), false)
	upds := tm.Update(p)
	assert.NotEmpty(t, upds)
	assert.Equal(t, 1, len(tm.GetPathList(GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_VPN})))
	rt := vrf.ImportRt.ToSlice()[0]
	assert.Len(t, tm.GetPathsByRT(rt, []bgp.Family{bgp.RF_IPv4_VPN}), 1)

	msgs, err := tm.DeleteVrf("vrfA")
	assert.NoError(t, err)
	assert.NotEmpty(t, msgs, "DeleteVrf should return withdraw paths for the local VPN path")

	// Feed them back like propagateUpdate does.
	for _, m := range msgs {
		tm.Update(m)
	}

	got := tm.GetPathList(GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_VPN})
	assert.Equal(t, 0, len(got), "VPN RIB must be empty after delete")
	assert.Nil(t, tm.GetPathsByRT(rt, []bgp.Family{bgp.RF_IPv4_VPN}), "RT index must be empty after delete")
}
