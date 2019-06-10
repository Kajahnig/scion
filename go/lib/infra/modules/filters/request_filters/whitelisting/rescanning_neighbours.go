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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/proto"
)

type NeighbourScanner struct {
	filter         *NeighbourFilter
	pathToTopoFile string
}

func (f *NeighbourScanner) Run(ctx context.Context) {
	topo, err := getTopo(f.pathToTopoFile)
	if err != nil {
		return
	}

	newList := map[addr.IA]struct{}{}

	for _, interf := range topo.IFInfoMap {
		if interf.LinkType != proto.LinkType_peer {
			newList[interf.ISD_AS] = struct{}{}
		}
	}

	f.filter.Lock.Lock()
	defer f.filter.Lock.Unlock()

	f.filter.Neighbours = newList
}

type UpNeighbourScanner struct {
	filter         *NeighbourFilter
	pathToTopoFile string
}

func (f *UpNeighbourScanner) Run(ctx context.Context) {
	topo, err := getTopo(f.pathToTopoFile)
	if err != nil {
		return
	}

	newList := map[addr.IA]struct{}{}

	for _, interf := range topo.IFInfoMap {
		if interf.LinkType == proto.LinkType_parent {
			newList[interf.ISD_AS] = struct{}{}
		}
	}

	f.filter.Lock.Lock()
	defer f.filter.Lock.Unlock()

	f.filter.Neighbours = newList
}

type DownNeighbourScanner struct {
	filter         *NeighbourFilter
	pathToTopoFile string
}

func (f *DownNeighbourScanner) Run(ctx context.Context) {
	topo, err := getTopo(f.pathToTopoFile)
	if err != nil {
		return
	}

	newList := map[addr.IA]struct{}{}

	for _, interf := range topo.IFInfoMap {
		if interf.LinkType == proto.LinkType_child {
			newList[interf.ISD_AS] = struct{}{}
		}
	}

	f.filter.Lock.Lock()
	defer f.filter.Lock.Unlock()

	f.filter.Neighbours = newList
}

type CoreNeighbourScanner struct {
	filter         *NeighbourFilter
	pathToTopoFile string
}

func (f *CoreNeighbourScanner) Run(ctx context.Context) {
	topo, err := getTopo(f.pathToTopoFile)
	if err != nil {
		return
	}

	newList := map[addr.IA]struct{}{}

	for _, interf := range topo.IFInfoMap {
		if interf.LinkType == proto.LinkType_core {
			newList[interf.ISD_AS] = struct{}{}
		}
	}

	f.filter.Lock.Lock()
	defer f.filter.Lock.Unlock()

	f.filter.Neighbours = newList
}
