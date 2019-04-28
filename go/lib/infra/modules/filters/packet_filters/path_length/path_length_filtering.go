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
// A path length filter filters packets according to their path length. It has the following settings:
// - allowEmptyPaths: if set allows packets without a path, thus from the local AS
// - disallowPaths:   if set disallows packets with a path, thus disallows packets from outside of the local AS
// - minPathLength:   (>1 if set) the minimum length a path must have (if a path is present)
// - maxPathLength:   (if zero it means the max is not set) the maximum length a path can have (if a path is present)
//
// example configurations are (not mentioned settings are set to the default value)
// only allow local traffic: allowEmptyPaths = true, disallowPaths = true
// only allow external traffic: minPathLength = 1
// only allow traffic from local AS and neighbours: allowEmptyPaths = true, minPathLength = 1, maxPathLength = 1
//

package path_length

import (
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/packet_filters"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
)

var _ packet_filters.PacketFilter = (*PathLengthFilter)(nil)

type PathLengthFilter struct {
	allowEmptyPaths bool
	disallowPaths   bool
	minPathLength   int
	maxPathLength   int
}

func NewPathLengthFilterFromConfig(cfg *PathLengthConfig) (*PathLengthFilter, error) {
	err := cfg.Validate()
	if err != nil {
		return nil, err
	}
	return &PathLengthFilter{
		allowEmptyPaths: cfg.AllowEmptyPaths,
		disallowPaths:   cfg.DisallowPaths,
		minPathLength:   cfg.MinPathLength,
		maxPathLength:   cfg.MaxPathLength,
	}, nil
}

func (f *PathLengthFilter) SCMPError() scmp.ClassType {
	return scmp.ClassType{
		Class: scmp.C_Filtering,
		Type:  scmp.T_F_PathLengthNotAccepted,
	}
}

func (f *PathLengthFilter) FilterPacket(pkt *snet.SCIONPacket) (filters.FilterResult, error) {
	path := pkt.SCIONPacketInfo.Path
	if path.IsEmpty() {
		if f.allowEmptyPaths {
			return filters.FilterAccept, nil
		}
		return filters.FilterDrop, nil
	}
	if f.disallowPaths {
		return filters.FilterDrop, nil
	}

	pathLength, err := determinePathLength(path)
	if err != nil {
		return filters.FilterError, err
	}

	if pathLength < f.minPathLength || (f.maxPathLength != 0 && pathLength > f.maxPathLength) {
		return filters.FilterDrop, nil
	}
	return filters.FilterAccept, nil
}

func determinePathLength(path *spath.Path) (int, error) {
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
			return -1, common.NewBasicError("Unable to determine length of corrupt path",
				nil, "currOff", offset, "max", len(path.Raw))
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
