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

package filters

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
	"time"
)

type OutsideWLSetting int
type LocalWLSetting int

const (
	//Settings for Filtering requests from outside the local AS
	// Whitelist all requests form the local ISD
	WLISD OutsideWLSetting = iota
	// Whitelist only the requests from neighbouring ASes
	WLAllNeighbours
	// Whitelist only the requests from neighbouring up- or downstream ASes
	WLUpAndDownNeighbours
	//Whitelists only core neighbours
	WLCoreNeighbours
	//Drop All requests from outside of the local AS
	NoOutsideWL
)

const (
	//Settings for Filtering requests from the local AS
	// Whitelist all requests form the local AS
	WLLocalAS LocalWLSetting = iota
	// Whitelist only local requests from infrastructure nodes
	WLLocalInfraNodes
	// Drop All requests from the local AS
	NoLocalWL
)

var _ AddrFilter = (*WhitelistFilter)(nil)

type WhitelistFilter struct {
	//contains the path to the topology file used to get identifiers of neighbouring ASes
	pathToTopoFile string
	//how often the topology file is rescanned
	rescanInterval float64
	//last time the topology file was scanned
	lastScan time.Time

	localIA           addr.IA
	neighbouringNodes map[addr.IA]string
	localInfraNodes   map[addr.IA]string //TODO: change the type to suitable address

	OutsideWLSetting
	LocalWLSetting
}

func NewWhitelistFilter(pathToTopoFile string, rescanInterval float64,
	outsideWLSetting OutsideWLSetting, localWLSetting LocalWLSetting) (*WhitelistFilter, error) {

	var localIA addr.IA

	topo, err := getTopo(pathToTopoFile)
	if err == nil {
		localIA = topo.ISD_AS
	}

	return &WhitelistFilter{
		pathToTopoFile:   pathToTopoFile,
		rescanInterval:   rescanInterval,
		localIA:          localIA,
		OutsideWLSetting: outsideWLSetting,
		LocalWLSetting:   localWLSetting,
	}, err
}

func (f *WhitelistFilter) FilterAddr(addr *snet.Addr) (FilterResult, error) {

	if time.Since(f.lastScan).Seconds() > f.rescanInterval {
		err := f.rescanTopoFile()
		if err != nil {
			return FilterError, err
		}
	}

	if addr.IA == f.localIA {
		//request is from local AS, apply local rules
		switch f.LocalWLSetting {
		case WLLocalAS:
			return FilterAccept, nil
		case NoLocalWL:
			return FilterDrop, nil
		case WLLocalInfraNodes:
			//TODO: check if addr is contained in local infra nodes
		default:
			return FilterError, common.NewBasicError("The local WL Setting has an illegal value",
				nil, "filterSetting", f.LocalWLSetting)
		}
	}

	//apparently the address is not from the local AS, so judge on outside rules:
	switch f.OutsideWLSetting {
	case NoOutsideWL:
		return FilterDrop, nil
	case WLISD:
		if addr.IA.I == f.localIA.I {
			return FilterAccept, nil
		}
		return FilterDrop, nil
	case WLAllNeighbours, WLUpAndDownNeighbours, WLCoreNeighbours:
		_, isPresent := f.neighbouringNodes[addr.IA]
		if isPresent {
			return FilterAccept, nil
		}
		return FilterDrop, nil
	default:
		return FilterError, common.NewBasicError("The outside WL Setting has an illegal value",
			nil, "filterSetting", f.OutsideWLSetting)
	}
}

func (f *WhitelistFilter) rescanTopoFile() error {

	topo, err := getTopo(f.pathToTopoFile)
	if err != nil {
		return err
	}

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

	if f.LocalWLSetting == WLLocalInfraNodes {
		//TODO: add local infrastructure node addresses to map
		//for every service: pub, bind, overlay?
	}

	return nil
}

func getTopo(pathToTopoFile string) (*topology.Topo, error) {
	return topology.LoadFromFile(pathToTopoFile)
}
