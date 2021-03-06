// Copyright 2019 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package beaconing

import (
	"context"
	"hash"
	"sync"

	"github.com/scionproto/scion/go/beacon_srv/internal/beacon"
	"github.com/scionproto/scion/go/beacon_srv/internal/ifstate"
	"github.com/scionproto/scion/go/beacon_srv/internal/onehop"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/proto"
)

// BeaconProvider provides beacons to send to neighboring ASes.
type BeaconProvider interface {
	BeaconsToPropagate(ctx context.Context) (<-chan beacon.BeaconOrErr, error)
}

var _ periodic.Task = (*Propagator)(nil)

// Propagator forwards beacons to neighboring ASes. In a core AS, the beacons
// are propagated to neighbors on core links. In a non-core AS, the beacons are
// forwarded on child links. Selection of the beacons is handled by the beacon
// provider, the propagator only filters AS loops.
type Propagator struct {
	segExtender
	sender   *onehop.Sender
	provider BeaconProvider
	core     bool
}

// NewPropagator creates a new beacon propagation task.
func NewPropagator(intfs *ifstate.Interfaces, mac hash.Hash, core bool, provider BeaconProvider,
	cfg Config, sender *onehop.Sender) (*Propagator, error) {

	cfg.InitDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	p := &Propagator{
		provider: provider,
		sender:   sender,
		core:     core,
		segExtender: segExtender{
			cfg:   cfg,
			mac:   mac,
			intfs: intfs,
			task:  "propagator",
		},
	}
	return p, nil
}

// Run propagates beacons provided by the beacon provider on all active target
// interfaces. In a core beacon server, core interfaces are the target
// interfaces. In a non-core beacon server, child interfaces are the target
// interfaces.
func (p *Propagator) Run(ctx context.Context) {
	if err := p.run(ctx); err != nil {
		log.Error("[Propagator] Unable to propagate beacons", "err", err)
	}
}

func (p *Propagator) run(ctx context.Context) error {
	beacons, err := p.provider.BeaconsToPropagate(ctx)
	if err != nil {
		return err
	}
	activeIntfs := p.activeIntfs()
	peers, nonActivePeers := sortedIntfs(p.intfs, proto.LinkType_peer)
	if len(nonActivePeers) > 0 {
		log.Debug("[Propagator] Ignore inactive peer links", "ifids", nonActivePeers)
	}
	wg := &sync.WaitGroup{}
	for bOrErr := range beacons {
		if bOrErr.Err != nil {
			log.Error("[Propagator] Unable to get beacon", "err", err)
			continue
		}
		p.startPropagate(bOrErr.Beacon, activeIntfs, peers, wg)
	}
	wg.Wait()
	return nil
}

// activeIntfs returns a list of active interface ids that beacons should be
// propagated to. In a core AS, these are all active core links. In a non-core
// AS, these are all active child links.
func (p *Propagator) activeIntfs() []common.IFIDType {
	var activeIntfs, nonActiveIntfs []common.IFIDType
	if p.core {
		activeIntfs, nonActiveIntfs = sortedIntfs(p.intfs, proto.LinkType_core)
	} else {
		activeIntfs, nonActiveIntfs = sortedIntfs(p.intfs, proto.LinkType_child)
	}
	if len(nonActiveIntfs) > 0 {
		log.Debug("[Propagator] Ignore inactive links", "ifids", nonActiveIntfs)
	}
	return activeIntfs
}

// startPropagate adds to the wait group and starts propagation of the beacon on
// all active interfaces.
func (p *Propagator) startPropagate(origBeacon beacon.Beacon, activeIntfs,
	peers []common.IFIDType, wg *sync.WaitGroup) {

	wg.Add(1)
	go func() {
		defer log.LogPanicAndExit()
		defer wg.Done()
		if err := p.propagate(origBeacon, activeIntfs, peers); err != nil {
			log.Error("[Propagator] Unable to propagate", "beacon", origBeacon, "err", err)
			return
		}
	}()
}

func (p *Propagator) propagate(origBeacon beacon.Beacon, activeIntfs,
	peers []common.IFIDType) error {

	raw, err := origBeacon.Segment.Pack()
	if err != nil {
		return err
	}
	var success ctr
	var expected int
	wg := sync.WaitGroup{}
	for _, egIfid := range activeIntfs {
		if p.shouldIgnore(origBeacon, egIfid) {
			continue
		}
		expected++
		bseg := origBeacon
		if bseg.Segment, err = seg.NewBeaconFromRaw(raw); err != nil {
			return common.NewBasicError("Unable to unpack beacon", err)
		}
		p.extendAndSend(bseg, egIfid, peers, &success, &wg)
	}
	wg.Wait()
	if success.c <= 0 && expected > 0 {
		return common.NewBasicError("None propagated", nil, "expected", expected)
	}
	log.Info("[Propagator] Successfully propagated", "beacon", origBeacon,
		"expected", expected, "count", success.c)
	return nil
}

// extendAndSend extends the path segment with the AS entry and sends it on the
// egress interface, all done in a goroutine to avoid head-of-line blocking.
func (p *Propagator) extendAndSend(bseg beacon.Beacon, egIfid common.IFIDType,
	peers []common.IFIDType, success *ctr, wg *sync.WaitGroup) {

	wg.Add(1)
	go func() {
		defer log.LogPanicAndExit()
		defer wg.Done()
		if err := p.extend(bseg.Segment, bseg.InIfId, egIfid, peers); err != nil {
			log.Error("[Propagator] Unable to extend beacon", "beacon", bseg, "err", err)
			return
		}
		topoInfo := p.intfs.Get(egIfid).TopoInfo()
		msg, err := packBeaconMsg(&seg.Beacon{Segment: bseg.Segment}, topoInfo.ISD_AS,
			egIfid, p.cfg.Signer)
		if err != nil {
			log.Error("[Propagator] Unable pack message", "beacon", bseg, "err", err)
			return
		}
		ov := topoInfo.InternalAddrs.PublicOverlay(topoInfo.InternalAddrs.Overlay)
		if err := p.sender.Send(msg, ov); err != nil {
			log.Error("[Propagator] Unable to send packet", "ifid", "err", err)
			return
		}
		success.Inc()
	}()
}

// shouldIgnore indicates whether a beacon should not be sent on the egress
// interface because it creates a loop.
func (p *Propagator) shouldIgnore(bseg beacon.Beacon, egIfid common.IFIDType) bool {
	intf := p.intfs.Get(egIfid)
	if intf == nil {
		return true
	}
	ia := intf.TopoInfo().ISD_AS
	for _, entry := range bseg.Segment.ASEntries {
		if entry.IA().Equal(ia) {
			return true
		}
	}
	return false
}
