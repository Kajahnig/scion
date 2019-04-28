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
//	There are the following external whitelisting filters, that filter addresses depending on their ISD-AS identifier:
//	- The Drop filter returns drop for all addresses
//	- The ISD Filter accepts addresses from the local ISD and drops everything else (the local AS is not influenced by
//	  by this filter, as requests from the local AS go into the Internal Filter)
//	- Neighbour Filters periodically scan the topology file and make a list of neighbouring ASes whose addresses get
//	  accepted. Which ASes are on the list depends on the used scanner (see New methods)
//		- Neighbour Filter: all neighbours of the local AS are on the whitelist
//		- Up Neighbour Filter: only directly upstream ASes of the local AS are on the list (parents)
//		- Down Neighbour Filter: only directly downstream ASes of the local AS are on the list (children)
//		- Core Neighbour Filter: only ASes connected with a core link to the local AS are on the list
//

package whitelisting

import (
	"context"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/request_filters"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/snet"
)

var _ request_filters.ExternalFilter = (*ISDFilter)(nil)

type ISDFilter struct {
	Isd addr.ISD
}

func (f *ISDFilter) FilterExternal(addr snet.Addr) (filters.FilterResult, error) {
	if addr.IA.I == f.Isd {
		return filters.FilterAccept, nil
	}
	return filters.FilterDrop, nil
}

func (f *ISDFilter) ErrorMessage() string {
	return ErrMsg
}

var _ request_filters.ExternalFilter = (*ISDFilter)(nil)

type NeighbourFilter struct {
	Neighbours map[addr.IA]bool
	Lock       sync.RWMutex
}

func NewNeighbourFilter(pathToTopoFile string, rescanInterval time.Duration) *NeighbourFilter {
	filter := &NeighbourFilter{}
	scanner := &NeighbourScanner{filter, pathToTopoFile}
	scanner.Run(context.Background())

	periodic.StartPeriodicTask(
		scanner,
		periodic.NewTicker(rescanInterval),
		rescanInterval)

	return filter
}

func NewUpNeighbourFilter(pathToTopoFile string, rescanInterval time.Duration) *NeighbourFilter {
	filter := &NeighbourFilter{}
	scanner := &UpNeighbourScanner{filter, pathToTopoFile}
	scanner.Run(context.Background())

	periodic.StartPeriodicTask(
		scanner,
		periodic.NewTicker(rescanInterval),
		rescanInterval)

	return filter
}

func NewDownNeighbourFilter(pathToTopoFile string, rescanInterval time.Duration) *NeighbourFilter {
	filter := &NeighbourFilter{}
	scanner := &DownNeighbourScanner{filter, pathToTopoFile}
	scanner.Run(context.Background())

	periodic.StartPeriodicTask(
		scanner,
		periodic.NewTicker(rescanInterval),
		rescanInterval)

	return filter
}

func NewCoreNeighbourFilter(pathToTopoFile string, rescanInterval time.Duration) *NeighbourFilter {
	filter := &NeighbourFilter{}
	scanner := &CoreNeighbourScanner{filter, pathToTopoFile}
	scanner.Run(context.Background())

	periodic.StartPeriodicTask(
		scanner,
		periodic.NewTicker(rescanInterval),
		rescanInterval)

	return filter
}

func (f *NeighbourFilter) FilterExternal(addr snet.Addr) (filters.FilterResult, error) {
	f.Lock.RLock()
	defer f.Lock.RUnlock()

	if _, isPresent := f.Neighbours[addr.IA]; isPresent {
		return filters.FilterAccept, nil
	}
	return filters.FilterDrop, nil
}

func (f *NeighbourFilter) ErrorMessage() string {
	return ErrMsg
}
