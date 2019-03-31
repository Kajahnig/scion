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
	"strconv"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

const (
	defaultRescanningInterval = 24 * time.Hour
	path_flag                 = "-path"
	rescanInterval_flag       = "-interval"
	outsideWL_flag            = "-outside"
	ISD_value                 = "ISD"
	allNeighbours_value       = "allN"
	upAndDownNeighbours_value = "upDownN"
	coreNeighbours_value      = "coreN"
	no_value                  = "no"
	localWL_flag              = "-local"
	AS_value                  = "AS"
	infra_value               = "infra"
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

func NewWhitelistFilter(pathToTopoFile string, rescanInterval time.Duration,
	outsideWLSetting OutsideWLSetting, localWLSetting LocalWLSetting) (*WhitelistFilter, error) {

	if rescanInterval <= 0 {
		return nil, common.NewBasicError("Whitelisting filter cannot be initialised with a zero or negative interval",
			nil, "rescanInterval", rescanInterval)
	}
	if outsideWLSetting == NoOutsideWL && localWLSetting == NoLocalWL {
		return nil, common.NewBasicError("Whitelisting filter cannot be with "+
			"no outside and no local whitelisting at the same time, this blocks all traffic.",
			nil, "outsideWLSettings", outsideWLSetting, "localWLSettings", localWLSetting)
	}

	topo, err := getTopo(pathToTopoFile)
	if err != nil {
		return nil, common.NewBasicError("Whitelisting filter cannot be initialised with an invalid topology file",
			nil, "err", err)
	}

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

func NewWhitelistFilterFromStrings(configParams []string, configDir string) (*WhitelistFilter, error) {
	var pathToTopoFile = configDir + "/" + "topology.json"
	var rescanInterval = defaultRescanningInterval
	var outsideSettings = NoOutsideWL
	var localSettings = NoLocalWL

	for i := 0; i < len(configParams); i += 2 {
		switch configParams[i] {
		case path_flag:
			pathToTopoFile = configParams[i+1]
		case rescanInterval_flag:
			interval, err := strconv.ParseInt(configParams[i+1], 10, 32)
			if err != nil {
				return nil, err
			}
			rescanInterval = time.Duration(interval) * time.Minute
		case outsideWL_flag:
			switch configParams[i+1] {
			case ISD_value:
				outsideSettings = WLISD
			case allNeighbours_value:
				outsideSettings = WLAllNeighbours
			case upAndDownNeighbours_value:
				outsideSettings = WLUpAndDownNeighbours
			case coreNeighbours_value:
				outsideSettings = WLCoreNeighbours
			}
		case localWL_flag:
			switch configParams[i+1] {
			case AS_value:
				localSettings = WLLocalAS
			case infra_value:
				localSettings = WLLocalInfraNodes
			}
		}
	}

	return NewWhitelistFilter(pathToTopoFile, rescanInterval, outsideSettings, localSettings)
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
