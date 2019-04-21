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

package whitelist_filters

import (
	"sync"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/snet"
)

var _ WLFilter = (*ISDFilter)(nil)

type ISDFilter struct {
	isd addr.ISD
}

func (f *ISDFilter) FilterPacket(addr *snet.SCIONAddress) (filters.FilterResult, error) {
	if addr.IA.I == f.isd {
		return filters.FilterAccept, nil
	}
	return filters.FilterDrop, nil
}

var _ WLFilter = (*NeighbourFilter)(nil)

type NeighbourFilter struct {
	Neighbours map[addr.IA]bool
	Lock       sync.RWMutex
}

func (f *NeighbourFilter) FilterPacket(addr *snet.SCIONAddress) (filters.FilterResult, error) {
	f.Lock.RLock()
	defer f.Lock.RUnlock()

	if _, isPresent := f.Neighbours[addr.IA]; isPresent {
		return filters.FilterAccept, nil
	}
	return filters.FilterDrop, nil
}
