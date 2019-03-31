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

	"github.com/pierrec/xxHash/xxHash32"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
)

type CBF struct {
	numCells     uint32
	filter1      cbfData
	filter2      cbfData
	usingFilter1 bool
	cbfDataMutex sync.Mutex
	resetMutex   sync.Mutex

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

	var data1, data2 cbfData
	if maxValue > 255 {
		data1 = &cbfData16{data: make([]uint16, numCells)}
		data2 = &cbfData16{data: make([]uint16, numCells)}
	} else {
		data1 = &cbfData8{data: make([]uint8, numCells)}
		data2 = &cbfData8{data: make([]uint8, numCells)}
	}

	return &CBF{
		numCells:     numCells,
		filter1:      data1,
		filter2:      data2,
		usingFilter1: true,
		numHashes:    numHashes,
		hash1:        xxHash32.New(uint32(scrypto.RandUint64() >> 32)),
		hash2:        xxHash32.New(uint32(scrypto.RandUint64() >> 32)),
		maxValue:     maxValue,
	}, nil
}

func (cbf *CBF) CheckIfRateLimitExceeded(key []byte) (bool, error) {
	cbf.hashMutex.Lock()
	h1, h2, err := cbf.getHashes(key)

	if err != nil {
		cbf.hashMutex.Unlock()
		return false, err
	}
	cbf.cbfDataMutex.Lock()
	defer cbf.cbfDataMutex.Unlock()
	cbf.hashMutex.Unlock()

	locations := make([]uint32, cbf.numHashes)

	var i uint32
	for i = 0; i < cbf.numHashes; i++ {
		locations[i] = (h1 + i*h2) % cbf.numCells
	}

	var minLocations []uint32
	var minValue uint32
	if cbf.usingFilter1 {
		minLocations, minValue = cbf.filter1.getMinimum(locations)
	} else {
		minLocations, minValue = cbf.filter2.getMinimum(locations)
	}

	if minValue >= cbf.maxValue {
		return true, nil
	}

	if cbf.usingFilter1 {
		cbf.filter1.increaseLocations(minLocations)
	} else {
		cbf.filter2.increaseLocations(minLocations)
	}
	return false, nil
}

func (cbf *CBF) Reset() {
	cbf.resetMutex.Lock()
	cbf.hashMutex.Lock()
	defer cbf.hashMutex.Unlock()
	cbf.cbfDataMutex.Lock()
	defer cbf.cbfDataMutex.Unlock()

	cbf.hash1 = xxHash32.New(uint32(scrypto.RandUint64() >> 32))
	cbf.hash2 = xxHash32.New(uint32(scrypto.RandUint64() >> 32))

	if cbf.usingFilter1 {
		cbf.usingFilter1 = false
		go func() {
			cbf.filter1.reset()
			cbf.resetMutex.Unlock()
		}()
	} else {
		cbf.usingFilter1 = true
		go func() {
			cbf.filter2.reset()
			cbf.resetMutex.Unlock()
		}()
	}
}

//only execute this when you have the hashLock
func (cbf *CBF) getHashes(key []byte) (uint32, uint32, error) {
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
