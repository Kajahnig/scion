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
	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
)

var SCMPClassType = scmp.ClassType{
	Class: scmp.C_Filtering,
	Type:  scmp.T_F_PathLengthNotValid,
}

var _ filters.PacketFilter = (*PathLengthFilter)(nil)

type PathLengthFilter struct {
	maxPathLength int
	minPathLength int
}

func NewPathLengthFilter(maxLength int, minLength int) (*PathLengthFilter, error) {

	//TODO: need to do something to ensure path length is not negative?

	return &PathLengthFilter{
		maxPathLength: maxLength,
		minPathLength: minLength,
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

	//TODO: count the number of path

	return 0, nil
}
