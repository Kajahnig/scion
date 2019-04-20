// Copyright 2019 ETH Zurich
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

package whitelisting

import (
	"context"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

const (
	defaultRescanningInterval = 24 * time.Hour
	ISD                       = "ISD"
	allNeighbours             = "allN"
	upAndDownNeighbours       = "upDownN"
	coreNeighbours            = "coreN"
	no                        = "no"
	AS                        = "AS"
	infra                     = "infra"
)

var _ filters.PacketFilter = (*WhitelistFilter)(nil)

type WhitelistFilter struct {
	//path to the topology file used to get identifiers of neighbouring ASes and infra structure nodes
	pathToTopoFile string
	//how often the topology file is rescanned, default is 24 Hours
	rescanInterval time.Duration
	localIA        addr.IA

	//map of whitelisted neighbouring nodes
	neighbouringNodes  map[addr.IA]string
	neighboursListLock sync.RWMutex

	//map of whitelisted infrastructure nodes
	localInfraNodes   map[string]string
	infraNodeListLock sync.RWMutex

	OutsideWLSetting
	LocalWLSetting
}

func NewWhitelistFilterFromConfig(cfg *WhitelistConfig) (*WhitelistFilter, error) {
	err := cfg.Validate()
	if err != nil {
		return nil, err
	}

	return newWhitelistFilter(cfg.PathToTopoFile, cfg.RescanInterval.Duration,
		cfg.OutsideWLSetting.OutsideWLSetting, cfg.LocalWLSetting.LocalWLSetting)
}

func newWhitelistFilter(pathToTopoFile string, rescanInterval time.Duration,
	outsideWLSetting OutsideWLSetting, localWLSetting LocalWLSetting) (*WhitelistFilter, error) {

	topo, _ := getTopo(pathToTopoFile)

	filter := &WhitelistFilter{
		pathToTopoFile:    pathToTopoFile,
		rescanInterval:    rescanInterval,
		localIA:           topo.ISD_AS,
		neighbouringNodes: map[addr.IA]string{},
		localInfraNodes:   map[string]string{},
		OutsideWLSetting:  outsideWLSetting,
		LocalWLSetting:    localWLSetting,
	}

	if filter.OutsideWLSetting > 1 {
		filter.fillNeighboursMap(topo)
	}

	if filter.LocalWLSetting == WLLocalInfraNodes {
		filter.fillInfraNodesMap(topo)
	}

	periodic.StartPeriodicTask(
		&TopoScanner{filter},
		periodic.NewTicker(rescanInterval),
		rescanInterval)

	return filter, nil
}

func getTopo(pathToTopoFile string) (*topology.Topo, error) {
	return topology.LoadFromFile(pathToTopoFile)
}

func (f *WhitelistFilter) rescanTopoFile() {
	topo, err := getTopo(f.pathToTopoFile)
	if err != nil {
		log.Error("Whitelisting filter failed to rescan topology file",
			"path", f.pathToTopoFile, "err", err)
	} else {
		if f.OutsideWLSetting > 1 {
			f.fillNeighboursMap(topo)
		}

		if f.LocalWLSetting == WLLocalInfraNodes {
			f.fillInfraNodesMap(topo)
		}
	}
}

func (f *WhitelistFilter) fillNeighboursMap(topo *topology.Topo) {
	f.neighboursListLock.Lock()
	defer f.neighboursListLock.Unlock()

	f.neighbouringNodes = map[addr.IA]string{}

	switch f.OutsideWLSetting {
	case WLAllNeighbours:
		for _, interf := range topo.IFInfoMap {
			f.neighbouringNodes[interf.ISD_AS] = ""
		}
	case WLUpAndDownNeighbours:
		for _, interf := range topo.IFInfoMap {
			if interf.LinkType == proto.LinkType_child || interf.LinkType == proto.LinkType_parent {
				f.neighbouringNodes[interf.ISD_AS] = ""
			}
		}
	case WLCoreNeighbours:
		for _, interf := range topo.IFInfoMap {
			if interf.LinkType == proto.LinkType_core {
				f.neighbouringNodes[interf.ISD_AS] = ""
			}
		}
	}
}

func (f *WhitelistFilter) fillInfraNodesMap(topo *topology.Topo) {
	f.infraNodeListLock.Lock()
	defer f.infraNodeListLock.Unlock()

	f.localInfraNodes = map[string]string{}

	for _, idAddrMap := range []topology.IDAddrMap{topo.DS, topo.BS, topo.CS, topo.PS, topo.SB, topo.RS, topo.SIG} {
		for _, topoAddr := range idAddrMap {
			if topoAddr.Overlay.IsIPv4() {
				f.localInfraNodes[topoAddr.IPv4.PublicAddr().L3.String()] = ""
			}
			if topoAddr.Overlay.IsIPv6() {
				f.localInfraNodes[topoAddr.IPv6.PublicAddr().L3.String()] = ""
			}
		}
	}
	for _, topoAddr := range topo.BR {
		if topoAddr.InternalAddrs.Overlay.IsIPv4() {
			f.localInfraNodes[topoAddr.InternalAddrs.IPv4.PublicOverlay.L3().String()] = ""
		}
		if topoAddr.InternalAddrs.Overlay.IsIPv6() {
			f.localInfraNodes[topoAddr.InternalAddrs.IPv6.PublicOverlay.L3().String()] = ""
		}
	}
}

type TopoScanner struct {
	filter *WhitelistFilter
}

func (f *TopoScanner) Run(ctx context.Context) {
	f.filter.rescanTopoFile()
}
