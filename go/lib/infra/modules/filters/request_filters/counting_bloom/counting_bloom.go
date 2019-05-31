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
	"sort"
	"sync"

	"github.com/pierrec/xxHash/xxHash32"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
)

type CBF struct {
	counterArray cbfData
	//For high numbers of cells, this is very wasteful in terms of memory usage.
	//Could be adapted by introducing a configurable locking factor (how many cells are locked with each other)
	counterLocks []sync.Mutex

	numCells  uint32
	numHashes uint32
	maxValue  int

	hash1 uint32
	hash2 uint32
}

func NewCBF(numCells uint32, numHashes uint32, maxValue int) (*CBF, error) {
	if numCells == 0 {
		return nil, common.NewBasicError("Can not instantiate CBF with 0 cells", nil)
	} else if numHashes == 0 {
		return nil, common.NewBasicError("Can not instantiate CBF with 0 hash functions", nil)
	} else if maxValue == 0 {
		return nil, common.NewBasicError("Can not instantiate CBF with 0 as maximum value", nil)
	} else if maxValue >= 65536 {
		return nil, common.NewBasicError("Can not instantiate CBF with a maximum value bigger than 16 bit", nil)
	}

	var data1 cbfData
	if maxValue > 255 {
		data1 = &cbfData16{data: make([]uint16, numCells)}
	} else {
		data1 = &cbfData8{data: make([]uint8, numCells)}
	}

	counterLocks := make([]sync.Mutex, numCells)

	return &CBF{
		counterArray: data1,
		counterLocks: counterLocks,
		numCells:     numCells,
		numHashes:    numHashes,
		maxValue:     maxValue,
		hash1:        uint32(scrypto.RandUint64() >> 32),
		hash2:        uint32(scrypto.RandUint64() >> 32),
	}, nil
}

func (cbf *CBF) CheckIfRateLimitExceeded(key []byte) (bool, error) {
	h1, h2, err := cbf.getHashes(key)

	if err != nil {
		return false, err
	}

	locations := cbf.getDistinctHashLocations(h1, h2)
	sort.Ints(locations)

	//lock the locations in increasing order.
	cbf.lockHashLocations(locations)
	//defer unlocking the locations
	defer cbf.unlockHashLocations(locations)

	minLocations, minValue := cbf.counterArray.getMinimum(locations)

	if minValue >= cbf.maxValue {
		return true, nil
	}

	cbf.counterArray.increaseLocations(minLocations)
	return false, nil
}

func (cbf CBF) getHashes(key []byte) (uint32, uint32, error) {
	hashfunc1 := xxHash32.New(cbf.hash1)
	hashfunc2 := xxHash32.New(cbf.hash2)

	_, err := hashfunc1.Write(key)
	if err != nil {
		return 0, 0, err
	}
	_, err = hashfunc2.Write(key)
	if err != nil {
		return 0, 0, err
	}

	h1 := hashfunc1.Sum32()
	h2 := hashfunc2.Sum32()

	return h1, h2, nil
}

func (cbf CBF) getDistinctHashLocations(h1, h2 uint32) []int {
	locations := make([]int, 0)

	for i := uint32(0); i < cbf.numHashes; i++ {
		possibleLocation := int((h1 + i*h2) % cbf.numCells)
		contains := false
		for _, loc := range locations {
			if loc == possibleLocation {
				contains = true
			}
		}
		if !contains {
			locations = append(locations, possibleLocation)
		}
	}
	return locations
}

func (cbf *CBF) lockHashLocations(locations []int) {
	for _, loc := range locations {
		cbf.counterLocks[loc].Lock()
	}
}

func (cbf *CBF) unlockHashLocations(locations []int) {
	for i := len(locations) - 1; i >= 0; i-- {
		cbf.counterLocks[locations[i]].Unlock()
	}
}

//this function should only be called if the whole data structure is locked for queries
func (cbf *CBF) Reset() {
	cbf.hash1 = uint32(scrypto.RandUint64() >> 32)
	cbf.hash2 = uint32(scrypto.RandUint64() >> 32)

	cbf.counterArray.reset()
}
