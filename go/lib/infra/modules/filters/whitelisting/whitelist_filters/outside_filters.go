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
	"context"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/snet"
)

var _ WLFilter = (*ISDFilter)(nil)

type ISDFilter struct {
	Isd addr.ISD
}

func (f *ISDFilter) FilterAddress(addr snet.SCIONAddress) (filters.FilterResult, error) {
	if addr.IA.I == f.Isd {
		return filters.FilterAccept, nil
	}
	return filters.FilterDrop, nil
}

var _ WLFilter = (*NeighbourFilter)(nil)

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

func (f *NeighbourFilter) FilterAddress(addr snet.SCIONAddress) (filters.FilterResult, error) {
	f.Lock.RLock()
	defer f.Lock.RUnlock()

	if _, isPresent := f.Neighbours[addr.IA]; isPresent {
		return filters.FilterAccept, nil
	}
	return filters.FilterDrop, nil
}
