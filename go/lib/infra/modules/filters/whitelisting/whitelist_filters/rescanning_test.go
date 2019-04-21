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
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
)

const (
	pathToFile = "../topology.json"
)

// This test uses the topology.json file in the same folder.
// It is a copy of the topology.json from ASff00_0_211 of the default topology.
var (
	peer221, _   = addr.IAFromString("2-ff00:0:221")
	peer111, _   = addr.IAFromString("1-ff00:0:111")
	child212, _  = addr.IAFromString("2-ff00:0:212")
	child222, _  = addr.IAFromString("2-ff00:0:222")
	parent210, _ = addr.IAFromString("2-ff00:0:210")
	otherAS, _   = addr.IAFromString("3-ff00:0:310")

	scannedInfraNodes     = map[string]bool{"127.0.0.209": true, "127.0.0.210": true, "127.0.0.211": true, "127.0.0.212": true}
	scannedNeighbours     = map[addr.IA]bool{peer221: true, peer111: true, child212: true, child222: true, parent210: true}
	scannedUpNeighbours   = map[addr.IA]bool{parent210: true}
	scannedDownNeighbours = map[addr.IA]bool{child212: true, child222: true}
)

func TestInfraNodesScanner_Run(t *testing.T) {
	filter := &InfraNodesFilter{
		InfraNodes: map[string]bool{"127.0.0.208": true},
	}
	scanner := InfraNodesScanner{filter, pathToFile}

	Convey("Scanning the topology should fill the filter map with infra nodes", t, func() {
		scanner.Run(context.Background())
		So(filter.InfraNodes, ShouldResemble, scannedInfraNodes)
	})
}

func TestNeighbourScanner_Run(t *testing.T) {
	filter := &NeighbourFilter{
		Neighbours: map[addr.IA]bool{otherAS: true},
	}
	scanner := NeighbourScanner{filter, pathToFile}

	Convey("Scanning the topology should fill the filter map with infra nodes", t, func() {
		scanner.Run(context.Background())
		So(filter.Neighbours, ShouldResemble, scannedNeighbours)
	})
}

func TestUpNeighbourScanner_Run(t *testing.T) {
	filter := &NeighbourFilter{
		Neighbours: map[addr.IA]bool{otherAS: true},
	}
	scanner := UpNeighbourScanner{filter, pathToFile}

	Convey("Scanning the topology should fill the filter map with infra nodes", t, func() {
		scanner.Run(context.Background())
		So(filter.Neighbours, ShouldResemble, scannedUpNeighbours)
	})
}

func TestDownNeighbourScanner_Run(t *testing.T) {
	filter := &NeighbourFilter{
		Neighbours: map[addr.IA]bool{otherAS: true},
	}
	scanner := DownNeighbourScanner{filter, pathToFile}

	Convey("Scanning the topology should fill the filter map with infra nodes", t, func() {
		scanner.Run(context.Background())
		So(filter.Neighbours, ShouldResemble, scannedDownNeighbours)
	})
}

func TestCoreNeighbourScanner_Run(t *testing.T) {
	filter := &NeighbourFilter{
		Neighbours: map[addr.IA]bool{otherAS: true},
	}
	scanner := CoreNeighbourScanner{filter, pathToFile}

	Convey("Scanning the topology should fill the filter map with infra nodes", t, func() {
		scanner.Run(context.Background())
		So(filter.Neighbours, ShouldResemble, map[addr.IA]bool{})
	})
}
