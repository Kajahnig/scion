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

package path_length

import (
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
)

var SCMPClassType = scmp.ClassType{
	Class: scmp.C_Filtering,
	Type:  scmp.T_F_PathLengthNotAccepted,
}

var _ filters.PacketFilter = (*PathLengthFilter)(nil)

type PathLengthFilter struct {
	minPathLength int
	maxPathLength int
}

func NewPathLengthFilter(minLength int, maxLength int) (*PathLengthFilter, error) {

	if minLength < 0 {
		return nil, common.NewBasicError("Unable to create path length filter with negative min length",
			nil, "minlength", minLength)
	}

	if maxLength < 0 {
		return nil, common.NewBasicError("Unable to create path length filter with negative max length",
			nil, "maxlength", maxLength)
	}

	if minLength > maxLength {
		return nil, common.NewBasicError("Unable to create path length filter with bigger min than max",
			nil, "minlength", minLength, "maxlength", maxLength)
	}

	return &PathLengthFilter{
		minPathLength: minLength,
		maxPathLength: maxLength,
	}, nil
}

func (f *PathLengthFilter) SCMPError() scmp.ClassType {
	return SCMPClassType
}

func (f *PathLengthFilter) FilterPacket(pkt *snet.SCIONPacket) (filters.FilterResult, error) {
	path := pkt.SCIONPacketInfo.Path
	pathLength, err := f.determinePathLength(path)

	if err != nil {
		return filters.FilterError, err
	}

	if pathLength > f.maxPathLength || pathLength < f.minPathLength {
		return filters.FilterDrop, nil
	}

	return filters.FilterAccept, nil
}

func (f *PathLengthFilter) determinePathLength(path *spath.Path) (int, error) {

	if path.IsEmpty() {
		return 0, nil
	}

	var offset = 0
	var pathLength int = 0

	for i := 0; i < 3; i++ {
		infoField, err := spath.InfoFFromRaw(path.Raw[offset:])
		if err != nil {
			return -1, err
		}
		offset += spath.InfoFieldLength + int(infoField.Hops)*spath.HopFieldLength
		pathLength += int(infoField.Hops)

		if offset == len(path.Raw) {
			break
		} else if offset > len(path.Raw) {
			return -1, common.NewBasicError("Unable to determine length of corrupt path", nil,
				"currOff", offset, "max", len(path.Raw))
		}
	}

	return pathLength, nil
}
