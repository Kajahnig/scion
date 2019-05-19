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
	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/request_filters"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
)

const PathLengthOneErrMsg = "Path too long"

var _ request_filters.ExternalFilter = (*PathLengthOneFilter)(nil)

type PathLengthOneFilter struct{}

func (f *PathLengthOneFilter) FilterExternal(addr snet.Addr) (filters.FilterResult, error) {
	if addr.Path.IsEmpty() {
		return filters.FilterDrop, nil
	}

	isOne, err := pathLengthOne(addr.Path)

	if err != nil {
		return filters.FilterError, err
	} else if isOne {
		return filters.FilterAccept, nil
	}
	return filters.FilterDrop, nil
}

func (f *PathLengthOneFilter) ErrorMessage() string {
	return PathLengthOneErrMsg
}

func pathLengthOne(path *spath.Path) (bool, error) {

	infoField, err := spath.InfoFFromRaw(path.Raw)
	if err != nil {
		return false, err
	}

	numHopfields := int(infoField.Hops)
	segLen := spath.InfoFieldLength + numHopfields*spath.HopFieldLength
	if segLen != len(path.Raw) || numHopfields < 2 {
		//the path has more than one segment or is corrupt
		//a path of length one needs at least two hop fields
		return false, nil
	}

	if numHopfields == 2 {
		//two hopfields, is path of length 2
		return true, nil
	}

	offset := spath.InfoFieldLength
	firstHopfield, err := spath.HopFFromRaw(path.Raw[offset:])
	if err != nil {
		return false, err
	}

	if !firstHopfield.VerifyOnly {
		// check next hop field to not be verfy only
		offset += 2 * spath.HopFieldLength
		thirdHopfield, err := spath.HopFFromRaw(path.Raw[offset:])
		if err != nil || !thirdHopfield.VerifyOnly {
			return false, err
		}
		return true, nil
	} else {
		//reverse path, we need to check the last three hopfields
		offset := segLen - 3*spath.HopFieldLength

		thirdLastHopField, err := spath.HopFFromRaw(path.Raw[offset:])
		if err != nil || !thirdLastHopField.VerifyOnly {
			return false, err
		}

		offset += spath.HopFieldLength
		secondLastHopField, err := spath.HopFFromRaw(path.Raw[offset:])
		if err != nil || secondLastHopField.VerifyOnly {
			return false, err
		}

		return true, nil
	}
}
