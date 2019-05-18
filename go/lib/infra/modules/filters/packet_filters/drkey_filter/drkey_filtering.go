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
//
//
// The DRKey filter filters packets depending on the validity of their drkey extension.
// If a drkey extension is present the filter returns accept if the contained MAC is valid and drop otherwise.
// If no drkey extension is present the filter result depends on the configuration of the filter, if internal
// (or external) filtering is disabled, internal (or external) packets are also accepted without an extension.
//

package drkey_filter

import (
	"bytes"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/packet_filters"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spse/scmp_auth"
)

var _ packet_filters.PacketFilter = (*DRKeyFilter)(nil)

type DRKeyFilter struct {
	internalFiltering            bool
	externalFiltering            bool
	mandatoryDRKeySCMPClassTypes [][]bool
}

func NewDRKeyFilterFromConfig(cfg *DRKeyConfig) *DRKeyFilter {

	matrix := make([][]bool, scmp.NumOfSCMPClasses())
	for i := range matrix {
		matrix[i] = make([]bool, scmp.NumOfMaxSCMPTypes())
	}

	for _, ct := range cfg.SCMPTypesWithDRKey {
		matrix[ct.Class][ct.Type] = true
	}

	return &DRKeyFilter{
		internalFiltering:            cfg.InternalFiltering,
		externalFiltering:            cfg.ExternalFiltering,
		mandatoryDRKeySCMPClassTypes: matrix,
	}
}

func (f *DRKeyFilter) FilterPacket(pkt *snet.SCIONPacket) (filters.FilterResult, error) {

	if pkt.L4Header.L4Type() == common.L4SCMP {
		hdr := pkt.L4Header.(*scmp.Hdr)
		if !f.mandatoryDRKeySCMPClassTypes[hdr.Class][hdr.Type] {
			return filters.FilterAccept, nil
		}
	}

	dir, receivedMac, err := extractDirAndMac(pkt)
	if err != nil {
		return filters.FilterError, err
	} else if receivedMac == nil {
		//there was no drkey extension
		if pkt.SCIONPacketInfo.Path.IsEmpty() {
			//it is an internal packet
			if f.internalFiltering {
				return filters.FilterDrop, nil
			}
		} else {
			//it is an external packet
			if f.externalFiltering {
				return filters.FilterDrop, nil
			}
		}
		//we don't do internal or external filtering
		return filters.FilterAccept, nil
	}

	key, err := findDRKey(dir)
	if err != nil {
		return filters.FilterError, err
	}

	calculatedMac, err := calculateMac(key, pkt)
	if err != nil {
		return filters.FilterError, err
	}

	if bytes.Equal(receivedMac, calculatedMac) {
		return filters.FilterAccept, nil
	}
	return filters.FilterDrop, nil
}

func extractDirAndMac(pkt *snet.SCIONPacket) (scmp_auth.Dir, common.RawBytes, error) {
	for _, ext := range pkt.Extensions {
		switch e := ext.(type) {
		case *scmp_auth.DRKeyExtn:
			return e.Direction, e.MAC, nil
		}
	}
	return scmp_auth.Dir(0), nil, nil
}

func calculateMac(key string, pkt *snet.SCIONPacket) (common.RawBytes, error) {
	//TODO: replace this function when implemented
	return nil, nil
}

func findDRKey(dir scmp_auth.Dir) (string, error) {
	//TODO: replace this function when implemented
	return "key", nil
}

func (f *DRKeyFilter) SCMPError() scmp.ClassType {
	return scmp.ClassType{
		Class: scmp.C_Filtering,
		Type:  scmp.T_F_NoDRKeyAuthentication,
	}
}
