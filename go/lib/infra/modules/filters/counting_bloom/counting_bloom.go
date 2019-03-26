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

package counting_bloom

import (
	"hash"
	"sync"

	"github.com/scionproto/scion/bazel-scion/external/com_github_pierrec_xxhash/xxHash32"

	"github.com/scionproto/scion/go/lib/common"
)

type CBF struct {
	numCells     uint32
	filter       cbfData
	cbfDataMutex sync.Mutex

	numHashes uint32
	hash1     hash.Hash32
	hash2     hash.Hash32
	hashMutex sync.Mutex

	maxValue uint32
}

func NewCBF(numCells uint32, numHashes uint32, maxValue uint32) (*CBF, error) {
	if numCells == 0 {
		return nil, common.NewBasicError("Can not instantiate CBF with 0 cells", nil)
	} else if numHashes == 0 {
		return nil, common.NewBasicError("Can not instantiate CBF with 0 hash functions", nil)
	} else if maxValue == 0 {
		return nil, common.NewBasicError("Can not instantiate CBF with 0 as maximum value", nil)
	} else if maxValue >= 65536 {
		return nil, common.NewBasicError("Can not instantiate CBF with a maximum value bigger than 16 bit", nil)
	}

	var data cbfData
	if maxValue > 255 {
		data = &cbfData16{data: make([]uint16, numCells)}
	} else {
		data = &cbfData8{data: make([]uint8, numCells)}
	}

	return &CBF{
		numCells:  numCells,
		filter:    data,
		numHashes: numHashes,
		hash1:     xxHash32.New(0),
		hash2:     xxHash32.New(2147483648),
		maxValue:  maxValue,
	}, nil
}

func (cbf *CBF) CheckIfRateLimitExceeded(key []byte) (bool, error) {
	h1, h2, err := cbf.getHashes(key)
	if err != nil {
		return false, err
	}

	locations := make([]uint32, cbf.numHashes)

	var i uint32
	for i = 0; i < cbf.numHashes; i++ {
		locations[i] = (h1 + i*h2) % cbf.numCells
	}

	cbf.cbfDataMutex.Lock()
	defer cbf.cbfDataMutex.Unlock()

	minLocations, minValue := cbf.filter.getMinimum(locations)

	if minValue >= cbf.maxValue {
		return true, nil
	}

	cbf.filter.increaseLocations(minLocations)
	return false, nil
}

func (cbf *CBF) getHashes(key []byte) (uint32, uint32, error) {
	cbf.hashMutex.Lock()
	defer cbf.hashMutex.Unlock()

	_, err := cbf.hash1.Write(key)
	if err != nil {
		return 0, 0, err
	}
	_, err = cbf.hash2.Write(key)
	if err != nil {
		return 0, 0, err
	}

	h1 := cbf.hash1.Sum32()
	h2 := cbf.hash2.Sum32()
	cbf.hash1.Reset()
	cbf.hash2.Reset()

	return h1, h2, nil
}
