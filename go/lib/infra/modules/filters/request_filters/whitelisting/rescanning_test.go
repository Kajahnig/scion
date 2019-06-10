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
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
)

const (
	pathToFile  = "./topology.json"
	pathToFile1 = "./topology1.json"
)

// This test uses the topology.json file in the same folder.
// It is a copy of the topology.json from ASff00_0_211 of the default topology.
// The second file is a copy of the topology.json from ASff00_0_120 of the default topology.
var (
	child111, _  = addr.IAFromString("1-ff00:0:111")
	child212, _  = addr.IAFromString("2-ff00:0:212")
	child222, _  = addr.IAFromString("2-ff00:0:222")
	parent210, _ = addr.IAFromString("2-ff00:0:210")
	otherAS, _   = addr.IAFromString("3-ff00:0:310")

	Core110, _  = addr.IAFromString("1-ff00:0:110")
	Core130, _  = addr.IAFromString("1-ff00:0:130")
	Child121, _ = addr.IAFromString("1-ff00:0:121")
	Core220, _  = addr.IAFromString("2-ff00:0:220")

	scannedInfraNodes  = map[string]struct{}{"127.0.0.209": {}, "127.0.0.210": {}, "127.0.0.211": {}, "127.0.0.212": {}}
	scannedInfraNodes1 = map[string]struct{}{"127.0.0.115": {}, "127.0.0.114": {}, "127.0.0.113": {}, "127.0.0.116": {},
		"127.0.0.117": {}, "127.0.0.118": {}}
	scannedNeighbours      = map[addr.IA]struct{}{child212: {}, child222: {}, parent210: {}}
	scannedNeighbours1     = map[addr.IA]struct{}{Core110: {}, Core130: {}, Core220: {}, child111: {}, Child121: {}}
	scannedUpNeighbours    = map[addr.IA]struct{}{parent210: {}}
	scannedUpNeighbours1   = map[addr.IA]struct{}{}
	scannedDownNeighbours  = map[addr.IA]struct{}{child212: {}, child222: {}}
	scannedDownNeighbours1 = map[addr.IA]struct{}{child111: {}, Child121: {}}
	scannedCoreNeighbours  = map[addr.IA]struct{}{}
	scannedCoreNeighbours1 = map[addr.IA]struct{}{Core110: {}, Core130: {}, Core220: {}}
)

func TestInfraNodesScanner_Run(t *testing.T) {
	filter := &InfraNodesFilter{
		InfraNodes: map[string]struct{}{"127.0.0.208": {}},
	}

	Convey("Scanning the topology should fill the filter map with infra nodes", t, func() {
		scanner := InfraNodesScanner{filter, pathToFile}
		scanner.Run(context.Background())
		So(filter.InfraNodes, ShouldResemble, scannedInfraNodes)
		scanner1 := InfraNodesScanner{filter, pathToFile1}
		scanner1.Run(context.Background())
		So(filter.InfraNodes, ShouldResemble, scannedInfraNodes1)
	})
}

func TestNeighbourScanner_Run(t *testing.T) {
	filter := &NeighbourFilter{
		Neighbours: map[addr.IA]struct{}{otherAS: {}},
	}

	Convey("Scanning the topology should fill the filter map with neighbouring nodes", t, func() {
		scanner := NeighbourScanner{filter, pathToFile}
		scanner.Run(context.Background())
		So(filter.Neighbours, ShouldResemble, scannedNeighbours)
		scanner1 := NeighbourScanner{filter, pathToFile1}
		scanner1.Run(context.Background())
		So(filter.Neighbours, ShouldResemble, scannedNeighbours1)
	})
}

func TestUpNeighbourScanner_Run(t *testing.T) {
	filter := &NeighbourFilter{
		Neighbours: map[addr.IA]struct{}{otherAS: {}},
	}

	Convey("Scanning the topology should fill the filter map with upstream neighbouring nodes", t, func() {
		scanner := UpNeighbourScanner{filter, pathToFile}
		scanner.Run(context.Background())
		So(filter.Neighbours, ShouldResemble, scannedUpNeighbours)
		scanner1 := UpNeighbourScanner{filter, pathToFile1}
		scanner1.Run(context.Background())
		So(filter.Neighbours, ShouldResemble, scannedUpNeighbours1)
	})
}

func TestDownNeighbourScanner_Run(t *testing.T) {
	filter := &NeighbourFilter{
		Neighbours: map[addr.IA]struct{}{otherAS: {}},
	}

	Convey("Scanning the topology should fill the filter map with downstream neighbouring nodes", t, func() {
		scanner := DownNeighbourScanner{filter, pathToFile}
		scanner.Run(context.Background())
		So(filter.Neighbours, ShouldResemble, scannedDownNeighbours)
		scanner1 := DownNeighbourScanner{filter, pathToFile1}
		scanner1.Run(context.Background())
		So(filter.Neighbours, ShouldResemble, scannedDownNeighbours1)
	})
}

func TestCoreNeighbourScanner_Run(t *testing.T) {
	filter := &NeighbourFilter{
		Neighbours: map[addr.IA]struct{}{otherAS: {}},
	}

	Convey("Scanning the topology should fill the filter map with neighbouring core nodes", t, func() {
		scanner := CoreNeighbourScanner{filter, pathToFile}
		scanner.Run(context.Background())
		So(filter.Neighbours, ShouldResemble, scannedCoreNeighbours)
		scanner1 := CoreNeighbourScanner{filter, pathToFile1}
		scanner1.Run(context.Background())
		So(filter.Neighbours, ShouldResemble, scannedCoreNeighbours1)
	})
}
