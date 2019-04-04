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

package drkey_filter

import (
	"bytes"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spse"
	"github.com/scionproto/scion/go/lib/spse/scmp_auth"
)

var SCMPClassType = scmp.ClassType{
	Class: scmp.C_Filtering,
	Type:  scmp.T_F_NoDRKeyAuthentication,
}

var _ filters.PacketFilter = (*DRKeyFilter)(nil)

type DRKeyFilter struct{}

func (f *DRKeyFilter) FilterPacket(pkt *snet.SCIONPacket) (filters.FilterResult, error) {

	dir, mac1, err := extractDirAndMac(pkt)
	if err != nil {
		return filters.FilterError, err
	} else if mac1 == nil {
		//there was no drkey extension
		return filters.FilterDrop, nil
	}

	mac2, err := calculateMac(dir, pkt)
	if err != nil {
		return filters.FilterError, err
	}

	if bytes.Equal(mac1, mac2) {
		return filters.FilterAccept, nil
	}
	return filters.FilterDrop, nil
}

func extractDirAndMac(pkt *snet.SCIONPacket) (scmp_auth.Dir, common.RawBytes, error) {
	var dir scmp_auth.Dir
	var mac common.RawBytes
	for _, ext := range pkt.Extensions {
		if ext.Type() == common.ExtnSCIONPacketSecurityType {
			secExt, err := ext.Pack()
			if err != nil {
				return scmp_auth.Dir(0), nil, err
			}
			secMode := spse.SecMode(secExt[0])
			if secMode == spse.ScmpAuthDRKey {
				dir = scmp_auth.Dir(secExt[1])
				mac = secExt[8:]
			}
		}
	}
	return dir, mac, nil
}
func calculateMac(dir scmp_auth.Dir, pkt *snet.SCIONPacket) (common.RawBytes, error) {
	//TODO: calculate the MAC of the Scion Packet
	return nil, nil
}

func (f *DRKeyFilter) SCMPError() scmp.ClassType {
	return SCMPClassType
}
