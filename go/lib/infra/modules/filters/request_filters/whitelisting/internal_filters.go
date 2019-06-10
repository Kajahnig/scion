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
//	There are the following internal whitelisting filters, that filter addresses depending on their IPs (thus the check
//	that the address is from the local AS should happen before calling the filter):
//	- The Drop filter returns drop for all addresses
//	- The Infra Nodes Filter periodically scan the topology file and makes a list of IPs from AS internal
//	  infrastructure nodes. If an address contains an IP on the list it is accepted otherwise dropped.
//	- The AS filter (only accept packets from the local AS) is implicit by not setting an internal filter at all
//	  (and a dropping filter for external traffic)
//

package whitelisting

import (
	"context"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/request_filters"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/snet"
)

var _ request_filters.InternalFilter = (*InfraNodesFilter)(nil)

type InfraNodesFilter struct {
	InfraNodes map[string]struct{}
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
