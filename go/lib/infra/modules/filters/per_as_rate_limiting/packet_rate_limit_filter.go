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

package per_as_rate_limiting

import (
	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/snet"
)

var _ filters.PacketFilter = (*PacketRateLimitFilter)(nil)

type PacketRateLimitFilter struct {
	localRateLimitFilter   *RateLimitFilter
	outsideRateLimitFilter *RateLimitFilter
}

func NewPacketRateLimitingFilterFromConfig(cfg *PacketRateLimitConfig) (*PacketRateLimitFilter, error) {
	var err error
	err = cfg.Validate()
	if err != nil {
		return nil, err
	}
	cfg.InitDefaults()

	localFilter, err := FilterFromConfig(cfg.LocalConfig)
	if err != nil {
		return nil, err
	}
	outsideFilter, err := FilterFromConfig(cfg.OutsideConfig)
	if err != nil {
		return nil, err
	}

	filter := &PacketRateLimitFilter{localFilter, outsideFilter}
	return filter, nil
}

func (f *PacketRateLimitFilter) FilterPacket(pkt *snet.SCIONPacket) (filters.FilterResult, error) {

	if pkt.Path.IsEmpty() {
		if f.localRateLimitFilter != nil {
			addrString := []byte(pkt.Source.Host.IP().String())
			return f.localRateLimitFilter.checkLimit(addrString)
		}
		return filters.FilterAccept, nil
	}

	if f.outsideRateLimitFilter != nil {
		addrString := []byte(pkt.Source.IA.String())
		return f.outsideRateLimitFilter.checkLimit(addrString)
	}
	return filters.FilterAccept, nil
}

func (f *PacketRateLimitFilter) SCMPError() scmp.ClassType {
	return scmp.ClassType{
		Class: scmp.C_Filtering,
		Type:  scmp.T_F_ASOrClientRateLimitReached,
	}
}
