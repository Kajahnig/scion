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

package whitelisting

import (
	"context"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/topology"
)

func getTopo(pathToTopoFile string) (*topology.Topo, error) {
	topo, err := topology.LoadFromFile(pathToTopoFile)
	if err != nil {
		log.Error("Failed to rescan topology file", "path", pathToTopoFile, "err", err)
		return nil, err
	}
	return topo, nil
}

type InfraNodesScanner struct {
	filter         *InfraNodesFilter
	pathToTopoFile string
}

func (s *InfraNodesScanner) Run(ctx context.Context) {
	topo, err := getTopo(s.pathToTopoFile)
	if err != nil {
		return
	}

	newList := map[string]bool{}

	for _, idAddrMap := range []topology.IDAddrMap{topo.DS, topo.BS, topo.CS, topo.PS, topo.SB, topo.RS, topo.SIG} {
		for _, topoAddr := range idAddrMap {
			if topoAddr.Overlay.IsIPv4() {
				newList[topoAddr.IPv4.PublicAddr().L3.String()] = true
			}
			if topoAddr.Overlay.IsIPv6() {
				newList[topoAddr.IPv6.PublicAddr().L3.String()] = true
			}
		}
	}
	for _, topoAddr := range topo.BR {
		if topoAddr.InternalAddrs.Overlay.IsIPv4() {
			newList[topoAddr.InternalAddrs.IPv4.PublicOverlay.L3().String()] = true
		}
		if topoAddr.InternalAddrs.Overlay.IsIPv6() {
			newList[topoAddr.InternalAddrs.IPv6.PublicOverlay.L3().String()] = true
		}
	}

	s.filter.Lock.Lock()
	defer s.filter.Lock.Unlock()

	s.filter.InfraNodes = newList
}
