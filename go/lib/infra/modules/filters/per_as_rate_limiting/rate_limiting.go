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
	"github.com/scionproto/scion/go/lib/infra/modules/filters/counting_bloom"
	"github.com/scionproto/scion/go/lib/snet"
	"time"

	"github.com/scionproto/scion/go/lib/scmp"
)

var SCMPClassType = scmp.ClassType{
	Class: scmp.C_Filtering,
	Type:  scmp.T_F_ASOrClientRateLimitReached,
}

func (f *PerASRateLimitFilter) SCMPError() scmp.ClassType {
	return SCMPClassType
}

func (f *PerASRateLimitFilter) FilterPacket(pkt *snet.SCIONPacket) (filters.FilterResult, error) {

	if pkt.Path.IsEmpty() {
		if f.localRateLimiting {
			return f.filterLocalPacket(pkt)
		}
		return filters.FilterAccept, nil
	}

	if f.outsideRateLimiting {
		return f.filterOutsidePacket(pkt)
	}
	return filters.FilterAccept, nil
}

func (f *PerASRateLimitFilter) filterLocalPacket(pkt *snet.SCIONPacket) (filters.FilterResult, error) {

	if time.Since(f.lastLocalUpdate).Seconds() > f.localFilterInfo.interval {
		cbf, err := counting_bloom.NewCBF(
			f.localFilterInfo.numCells,
			f.localFilterInfo.numHashFunc,
			f.localFilterInfo.maxValue,
		)
		if err != nil {
			return filters.FilterError, err
		}
		f.localFilter = cbf
	}

	rateLimitExceeded, err := f.localFilter.CheckIfRateLimitExceeded([]byte(pkt.Source.Host.IP().String()))

	if err != nil {
		return filters.FilterError, err
	}
	if rateLimitExceeded {
		return filters.FilterDrop, nil
	}
	return filters.FilterAccept, nil
}

func (f *PerASRateLimitFilter) filterOutsidePacket(pkt *snet.SCIONPacket) (filters.FilterResult, error) {

	if time.Since(f.lastOutsideUpdate).Seconds() > f.outsideFilterInfo.interval {
		cbf, err := counting_bloom.NewCBF(
			f.outsideFilterInfo.numCells,
			f.outsideFilterInfo.numHashFunc,
			f.outsideFilterInfo.maxValue,
		)
		if err != nil {
			return filters.FilterError, err
		}
		f.outsideFilter = cbf
	}

	rateLimitExceeded, err := f.outsideFilter.CheckIfRateLimitExceeded([]byte(pkt.Source.IA.String()))
	if err != nil {
		return filters.FilterError, err
	}
	if rateLimitExceeded {
		return filters.FilterDrop, nil
	}
	return filters.FilterAccept, nil
}
