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

	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/snet"
)

var _ WLFilter = (*InfraNodesFilter)(nil)
var _ filters.InternalFilter = (*InfraNodesFilter)(nil)

type InfraNodesFilter struct {
	InfraNodes map[string]bool
	Lock       sync.RWMutex
}

func NewInfraNodesFilter(pathToTopoFile string, rescanInterval time.Duration) *InfraNodesFilter {
	filter := &InfraNodesFilter{}
	scanner := &InfraNodesScanner{filter, pathToTopoFile}
	scanner.Run(context.Background())

	periodic.StartPeriodicTask(
		scanner,
		periodic.NewTicker(rescanInterval),
		rescanInterval)

	return filter
}

func (f *InfraNodesFilter) FilterAddress(addr snet.SCIONAddress) (filters.FilterResult, error) {
	f.Lock.RLock()
	defer f.Lock.RUnlock()

	if _, isPresent := f.InfraNodes[addr.Host.IP().String()]; isPresent {
		return filters.FilterAccept, nil
	}
	return filters.FilterDrop, nil
}

func (f *InfraNodesFilter) FilterInternal(addr snet.Addr) (filters.FilterResult, error) {
	f.Lock.RLock()
	defer f.Lock.RUnlock()

	if _, isPresent := f.InfraNodes[addr.Host.L3.IP().String()]; isPresent {
		return filters.FilterAccept, nil
	}
	return filters.FilterDrop, nil
}

func (f *InfraNodesFilter) ErrorMessage() string {
	return ErrMsg
}
