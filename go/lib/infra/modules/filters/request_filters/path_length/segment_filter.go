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

package path_length

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/request_filters"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
)

const SegmentNumErrMsg = "Path too long"

var _ request_filters.ExternalFilter = (*SegmentFilter)(nil)

type SegmentFilter struct {
	Isd    addr.ISD
	IsCore bool //if yes the max number of allowed segments is 1, otherwise 2, peering paths not allowed by default
}

func (f *SegmentFilter) FilterExternal(addr snet.Addr) (filters.FilterResult, error) {
	if addr.Path.IsEmpty() {
		return filters.FilterDrop, nil
	}

	if addr.IA.I == f.Isd {
		return filters.FilterAccept, nil
	}

	return f.filterDependingOnSegNum(addr.Path)
}

func (f *SegmentFilter) ErrorMessage() string {
	return SegmentNumErrMsg
}

func (f *SegmentFilter) filterDependingOnSegNum(path *spath.Path) (filters.FilterResult, error) {

	infoField1, err := spath.InfoFFromRaw(path.Raw)
	if err != nil {
		return filters.FilterError, err
	}
	if infoField1.Peer {
		return filters.FilterDrop, nil
	}

	seg1Len := spath.InfoFieldLength + int(infoField1.Hops)*spath.HopFieldLength
	if seg1Len > len(path.Raw) {
		return filters.FilterError,
			common.NewBasicError("Corrupt path, segment is longer than path", nil)
	} else if seg1Len == len(path.Raw) {
		return filters.FilterAccept, nil
	}

	if f.IsCore {
		//because path has more than one segment
		return filters.FilterDrop, nil
	}

	//otherwise we check if it has 2 or 3 segments
	infoField2, err := spath.InfoFFromRaw(path.Raw[seg1Len:])
	if err != nil {
		return filters.FilterError, err
	}
	seg2Len := spath.InfoFieldLength + int(infoField2.Hops)*spath.HopFieldLength
	if seg1Len+seg2Len == len(path.Raw) {
		return filters.FilterAccept, nil
	}
	return filters.FilterDrop, nil
}
