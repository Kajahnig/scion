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
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/snet"
)

var SCMPClassType = scmp.ClassType{
	Class: scmp.C_Filtering,
	Type:  scmp.T_F_NotOnWhitelist,
}

func (f *WhitelistFilter) SCMPError() scmp.ClassType {
	return SCMPClassType
}

func (f *WhitelistFilter) FilterPacket(pkt *snet.SCIONPacket) (filters.FilterResult, error) {

	address := pkt.Source

	if address.IA == f.localIA {
		return f.filterLocalAddr(address)
	} else {
		return f.filterRemoteAddr(address)
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
