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
	"fmt"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
)

const (
	defaultTestInterval = 100 * time.Millisecond
	pathToFile          = "./topology.json"
	pathToFileEmptyFile = "./empty_topology.json"
)

// This test uses the topology.json file in the same folder.
// It is a copy of the topology.json from ASff00_0_211 of the default topology.
var (
	peer221, _   = addr.IAFromString("2-ff00:0:221")
	peer111, _   = addr.IAFromString("1-ff00:0:111")
	child212, _  = addr.IAFromString("2-ff00:0:212")
	child222, _  = addr.IAFromString("2-ff00:0:222")
	parent210, _ = addr.IAFromString("2-ff00:0:210")

	localIA, _ = addr.IAFromString("2-ff00:0:211")

	scannedNeighbours          = map[addr.IA]string{peer221: "", peer111: "", child212: "", child222: "", parent210: ""}
	scannedUpAndDownNeighbours = map[addr.IA]string{child212: "", child222: "", parent210: ""}
	emptyNeighboursMap         = map[addr.IA]string{}
	scannedInfraNodes          = map[string]string{"127.0.0.209": "", "127.0.0.210": "", "127.0.0.211": "", "127.0.0.212": ""}
	emptyInfraNodesMap         = map[string]string{}
)

func Test_newWhitelistFilter(t *testing.T) {

	Convey("Creating a new filter", t, func() {

		Convey("With valid settings", func() {

			filter, err := newWhitelistFilter(pathToFile, defaultRescanningInterval, WLAllNeighbours, WLLocalInfraNodes)

			Convey("Should not return an error", func() {
				So(err, ShouldBeNil)
			})

			Convey("Should set the local IA address of the filter", func() {
				So(filter.localIA, ShouldResemble, localIA)
			})

			Convey("Should fill the maps of the filter", func() {
				So(filter.neighbouringNodes, ShouldResemble, scannedNeighbours)
				So(filter.localInfraNodes, ShouldResemble, scannedInfraNodes)
			})
		})
	})
}

func Test_rescanTopoFile(t *testing.T) {

	Convey("Rescanning the topology file on a filter with outside settings", t, func() {

		tests := []struct {
			outsideSettings    OutsideWLSetting
			neighboursMap      map[addr.IA]string
			contentDescription string
		}{

			{WLAllNeighbours, scannedNeighbours,
				"Should fill the map of neighbouring nodes with all neighbours"},
			{WLUpAndDownNeighbours, scannedUpAndDownNeighbours,
				"Should fill the map of neighbouring nodes with up and downstream neighbours"},
			{WLCoreNeighbours, emptyNeighboursMap,
				"Should fill the map of neighbouring nodes with core neighbours"},
			{NoOutsideWL, emptyNeighboursMap,
				"Should not fill the map of neighbouring nodes"},
			{WLISD, emptyNeighboursMap,
				"Should not fill the map of neighbouring nodes"},
		}

		for _, test := range tests {

			Convey(test.outsideSettings.toString(), func() {

				filter, err := newWhitelistFilter(pathToFileEmptyFile, defaultRescanningInterval, test.outsideSettings, WLLocalAS)

				So(err, ShouldBeNil)
				So(filter.neighbouringNodes, ShouldBeEmpty)
				So(filter.localInfraNodes, ShouldBeEmpty)

				filter.pathToTopoFile = pathToFile

				filter.rescanTopoFile()

				Convey(test.contentDescription, func() {
					So(filter.neighbouringNodes, ShouldResemble, test.neighboursMap)
				})

				Convey("Should not fill the local infra nodes map", func() {
					So(filter.localInfraNodes, ShouldBeEmpty)
				})
			})
		}

	})
	Convey("Rescanning the topology file on a filter with local settings", t, func() {

		localTests := []struct {
			localSettings      LocalWLSetting
			localInfraNodeMap  map[string]string
			contentDescription string
		}{

			{WLLocalAS, emptyInfraNodesMap,
				"Should not fill the local infra nodes map"},
			{WLLocalInfraNodes, scannedInfraNodes,
				"Should fill the local infra nodes map with local infra IPs"},
			{NoLocalWL, emptyInfraNodesMap,
				"Should not fill the local infra nodes map"},
		}

		for _, test := range localTests {

			Convey(test.localSettings.toString(), func() {

				filter, err := newWhitelistFilter(pathToFileEmptyFile, defaultRescanningInterval, WLISD, test.localSettings)

				So(err, ShouldBeNil)
				So(filter.neighbouringNodes, ShouldBeEmpty)
				So(filter.localInfraNodes, ShouldBeEmpty)

				filter.pathToTopoFile = pathToFile

				filter.rescanTopoFile()

				Convey(test.contentDescription, func() {
					So(filter.localInfraNodes, ShouldResemble, test.localInfraNodeMap)
				})

				Convey("Should not fill the map of neighbouring nodes", func() {
					So(filter.neighbouringNodes, ShouldBeEmpty)
				})
			})
		}
	})
}

func Test_periodicRescanningOfTheTopoFile(t *testing.T) {

	Convey("Creating a filter with settings: WLAllNeighbours, WLLocalInfraNodes", t, func() {

		filter, _ := newWhitelistFilter(pathToFileEmptyFile, defaultTestInterval, WLAllNeighbours, WLLocalInfraNodes)

		Convey("Should initialize the maps empty because the topology file is empty", func() {
			So(filter.neighbouringNodes, ShouldBeEmpty)
			So(filter.localInfraNodes, ShouldBeEmpty)
		})

		filter.pathToTopoFile = pathToFile

		Convey(fmt.Sprintf("But setting the topofile path to another file and waiting %v",
			defaultTestInterval), func() {

			time.Sleep(defaultTestInterval * 2)
			Convey("Should fill the neighbours map", func() {
				So(filter.neighbouringNodes, ShouldResemble, scannedNeighbours)
			})
			Convey("Should fill the infra nodes map", func() {
				So(filter.localInfraNodes, ShouldResemble, scannedInfraNodes)
			})
		})
	})

	Convey("Creating a filter with settings: NoOutsideWL, WLLocalInfraNodes", t, func() {

		filter, _ := newWhitelistFilter(pathToFileEmptyFile, defaultTestInterval, NoOutsideWL, WLLocalInfraNodes)

		Convey("Should initialize the maps empty because the topology file is empty", func() {
			So(filter.neighbouringNodes, ShouldBeEmpty)
			So(filter.localInfraNodes, ShouldBeEmpty)
		})

		filter.pathToTopoFile = pathToFile

		Convey(fmt.Sprintf("But setting the topofile path to another file and waiting %v",
			defaultTestInterval), func() {

			time.Sleep(defaultTestInterval * 2)
			Convey("Should not fill the neighbours map", func() {
				So(filter.neighbouringNodes, ShouldResemble, emptyNeighboursMap)
			})
			Convey("Should fill the infra nodes map", func() {
				So(filter.localInfraNodes, ShouldResemble, scannedInfraNodes)
			})
		})
	})

	Convey("Creating a filter with settings: WLAllNeighbours, NoLocalWL", t, func() {

		filter, _ := newWhitelistFilter(pathToFileEmptyFile, defaultTestInterval, WLAllNeighbours, NoLocalWL)

		Convey("Should initialize the maps empty because the topology file is empty", func() {
			So(filter.neighbouringNodes, ShouldBeEmpty)
			So(filter.localInfraNodes, ShouldBeEmpty)
		})

		filter.pathToTopoFile = pathToFile

		Convey(fmt.Sprintf("But setting the topofile path to another file and waiting %v",
			defaultTestInterval), func() {

			time.Sleep(defaultTestInterval * 2)
			Convey("Should fill the neighbours map", func() {
				So(filter.neighbouringNodes, ShouldResemble, scannedNeighbours)
			})
			Convey("Should not fill the infra nodes map", func() {
				So(filter.localInfraNodes, ShouldResemble, emptyInfraNodesMap)
			})
		})
	})

	Convey("Creating a filter with settings: WLISD, WLLocalAS", t, func() {

		filter, _ := newWhitelistFilter(pathToFileEmptyFile, defaultTestInterval, WLISD, WLLocalAS)

		Convey("Should initialize the maps empty because the topology file is empty", func() {
			So(filter.neighbouringNodes, ShouldBeEmpty)
			So(filter.localInfraNodes, ShouldBeEmpty)
		})

		filter.pathToTopoFile = pathToFile

		Convey(fmt.Sprintf("But setting the topofile path to another file and waiting %v",
			defaultTestInterval), func() {

			time.Sleep(defaultTestInterval * 2)
			Convey("Should not fill the neighbours map", func() {
				So(filter.neighbouringNodes, ShouldResemble, emptyNeighboursMap)
			})
			Convey("Should not fill the infra nodes map", func() {
				So(filter.localInfraNodes, ShouldResemble, emptyInfraNodesMap)
			})
		})
	})
}
