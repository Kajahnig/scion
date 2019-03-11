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
	"strconv"
)

var SCMPClassType = scmp.ClassType{
	Class: scmp.C_Filtering,
	Type:  scmp.T_F_PathLengthNotAccepted,
}

var (
	minLength_flag = "-min"
	maxLength_flag = "-max"
)

var _ filters.PacketFilter = (*PathLengthFilter)(nil)

type PathLengthFilter struct {
	minPathLength int
	maxPathLength int
}

func NewPathLengthFilter(minLength int, maxLength int) (*PathLengthFilter, error) {

	if minLength < 0 {
		return nil, common.NewBasicError("Unable to create path length filter with negative/invalid min length",
			nil, "minlength", minLength)
	}

	if maxLength < 0 {
		return nil, common.NewBasicError("Unable to create path length filter with negative/invalid max length",
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

func NewPathLengthFilterFromStrings(configParams []string) (*PathLengthFilter, error) {
	var minLength = 0
	var maxLength = -1

	for i := 0; i < len(configParams); i += 2 {
		switch configParams[i] {
		case minLength_flag:
			minLength64, err := strconv.ParseInt(configParams[i+1], 10, 32)
			if err != nil {
				return nil, err
			}
			minLength = int(minLength64)
		case maxLength_flag:
			maxLength64, err := strconv.ParseInt(configParams[i+1], 10, 32)
			if err != nil {
				return nil, err
			}
			maxLength = int(maxLength64)
		}
	}

	filter, err := NewPathLengthFilter(minLength, maxLength)
	if err != nil {
		return nil, err
	}
	return filter, nil
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
	var pathLength = 0

	for i := 0; i < 3; i++ {
		infoField, err := spath.InfoFFromRaw(path.Raw[offset:])
		if err != nil {
			return -1, err
		}
		segLen := spath.InfoFieldLength + int(infoField.Hops)*spath.HopFieldLength
		endOfSegment := offset + segLen
		if endOfSegment > len(path.Raw) {
			return -1, common.NewBasicError("Unable to determine length of corrupt path", nil,
				"currOff", offset, "max", len(path.Raw))
		}
		hopFieldCounter := 0
		firstXover := true
		for offset += spath.InfoFieldLength; offset < endOfSegment; offset += spath.HopFieldLength {
			hop, err := spath.HopFFromRaw(path.Raw[offset:])
			if err != nil {
				return -1, err
			}
			if !hop.VerifyOnly {
				if hop.Xover {
					if firstXover {
						firstXover = false
						hopFieldCounter += 1
					}
				} else {
					hopFieldCounter += 1
				}
			}
		}

		if i == 0 && infoField.Peer {
			hopFieldCounter += 1
		}
		pathLength += hopFieldCounter - 1
		offset = endOfSegment

		if offset == len(path.Raw) {
			break
		}
	}
	return pathLength, nil
}
