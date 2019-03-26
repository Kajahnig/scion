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
	"strconv"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

const (
	defaultRescanningInterval = float64(24 * 60) //minutes in a day
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

var SCMPClassType = scmp.ClassType{
	Class: scmp.C_Filtering,
	Type:  scmp.T_F_NotOnWhitelist,
}

var _ filters.PacketFilter = (*WhitelistFilter)(nil)

type WhitelistFilter struct {
	//contains the path to the topology file used to get identifiers of neighbouring ASes
	pathToTopoFile string
	//how often the topology file is rescanned in minutes, for default see var above
	rescanInterval float64
	//last time the topology file was scanned
	lastScan time.Time
	localIA  addr.IA

	//map of whitelisted neighbouring nodes
	neighbouringNodes map[addr.IA]string
	//map of whitelisted infrastructure nodes
	localInfraNodes map[string]string

	//read write lock to lock neighbouring nodes list while it gets updated by rescanTopoFile
	neighboursListLock sync.RWMutex
	//read write lock to lock infrastructure nodes list while it gets updated by rescanTopoFile
	infraNodeListLock sync.RWMutex

	OutsideWLSetting
	LocalWLSetting
}

func NewWhitelistFilter(pathToTopoFile string, rescanInterval float64,
	outsideWLSetting OutsideWLSetting, localWLSetting LocalWLSetting) (*WhitelistFilter, error) {

	if rescanInterval <= 0 {
		return nil, common.NewBasicError("Whitelisting filter cannot be initialised with negative rescanning interval",
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

	localIA := topo.ISD_AS

	return &WhitelistFilter{
		pathToTopoFile:    pathToTopoFile,
		rescanInterval:    rescanInterval,
		localIA:           localIA,
		neighbouringNodes: map[addr.IA]string{},
		localInfraNodes:   map[string]string{},
		OutsideWLSetting:  outsideWLSetting,
		LocalWLSetting:    localWLSetting,
	}, nil
}

func NewWhitelistFilterFromStrings(configParams []string, configDir string) (*WhitelistFilter, error) {
	var pathToTopoFile = ""
	var rescanInterval float64 = defaultRescanningInterval
	var outsideSettings = NoOutsideWL
	var localSettings = NoLocalWL
	var err error

	for i := 0; i < len(configParams); i += 2 {
		switch configParams[i] {
		case path_flag:
			pathToTopoFile = configParams[i+1]
		case rescanInterval_flag:
			rescanInterval, err = strconv.ParseFloat(configParams[i+1], 64)
			if err != nil {
				return nil, err
			}
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

	if pathToTopoFile == "" {
		pathToTopoFile = configDir + "/" + "topology.json"
	}

	filter, err := NewWhitelistFilter(pathToTopoFile, rescanInterval,
		outsideSettings, localSettings)
	if err != nil {
		return nil, err
	}
	return filter, nil
}

func getTopo(pathToTopoFile string) (*topology.Topo, error) {
	return topology.LoadFromFile(pathToTopoFile)
}

func (f *WhitelistFilter) SCMPError() scmp.ClassType {
	return SCMPClassType
}

func (f *WhitelistFilter) FilterPacket(pkt *snet.SCIONPacket) (filters.FilterResult, error) {

	f.rescanTopoFileIfNecessary()

	address := pkt.Source

	if address.IA == f.localIA {
		return f.filterLocalAddr(address)
	} else {
		return f.filterRemoteAddr(address)
	}
}

func (f *WhitelistFilter) rescanTopoFileIfNecessary() {
	if f.OutsideWLSetting > 1 || f.LocalWLSetting == WLLocalInfraNodes {
		if time.Since(f.lastScan).Minutes() > f.rescanInterval {
			err := f.rescanTopoFile()
			if err != nil {
				log.Error("Whitelisting filter failed to rescan topology file",
					"path", f.pathToTopoFile, "err", err)
			}
		}
	}
}

func (f *WhitelistFilter) rescanTopoFile() error {

	topo, err := getTopo(f.pathToTopoFile)
	if err != nil {
		return err
	}

	f.lastScan = time.Now()

	f.fillNeighboursMap(topo)

	if f.LocalWLSetting == WLLocalInfraNodes {
		f.fillInfraNodesMap(topo)
	}

	return nil
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

func (f *WhitelistFilter) filterLocalAddr(addr snet.SCIONAddress) (filters.FilterResult, error) {

	switch f.LocalWLSetting {
	case WLLocalAS:
		return filters.FilterAccept, nil
	case NoLocalWL:
		return filters.FilterDrop, nil
	case WLLocalInfraNodes:
		return f.filterDependingOnInfraNodeWL(addr)
	default:
		return filters.FilterError, common.NewBasicError("The local WL Setting has an illegal value",
			nil, "filterSetting", f.LocalWLSetting)
	}
}

func (f *WhitelistFilter) filterDependingOnInfraNodeWL(addr snet.SCIONAddress) (filters.FilterResult, error) {
	f.infraNodeListLock.RLock()
	defer f.infraNodeListLock.RUnlock()

	if _, isPresent := f.localInfraNodes[addr.Host.IP().String()]; isPresent {
		return filters.FilterAccept, nil
	}
	return filters.FilterDrop, nil
}

func (f *WhitelistFilter) filterRemoteAddr(addr snet.SCIONAddress) (filters.FilterResult, error) {

	switch f.OutsideWLSetting {
	case NoOutsideWL:
		return filters.FilterDrop, nil
	case WLISD:
		if addr.IA.I == f.localIA.I {
			return filters.FilterAccept, nil
		}
		return filters.FilterDrop, nil
	case WLAllNeighbours, WLUpAndDownNeighbours, WLCoreNeighbours:
		return f.filterDependingOnNeighboursWL(addr)
	default:
		return filters.FilterError, common.NewBasicError("The outside WL Setting has an illegal value",
			nil, "filterSetting", f.OutsideWLSetting)
	}
}

func (f *WhitelistFilter) filterDependingOnNeighboursWL(addr snet.SCIONAddress) (filters.FilterResult, error) {
	f.neighboursListLock.RLock()
	defer f.neighboursListLock.RUnlock()

	if _, isPresent := f.neighbouringNodes[addr.IA]; isPresent {
		return filters.FilterAccept, nil
	}
	return filters.FilterDrop, nil
}
