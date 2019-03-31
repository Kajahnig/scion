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
	"strings"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
)

const (
	defaultInterval     = 24 * time.Hour
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

func Test_NewWhitelistFilter(t *testing.T) {

	Convey("Creating a new filter", t, func() {

		Convey("With valid settings", func() {

			filter, err := NewWhitelistFilter(pathToFile, defaultInterval, WLAllNeighbours, WLLocalInfraNodes)

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

		tests := []struct {
			description        string
			pathToTopoFile     string
			rescanningInterval time.Duration
			outsideSettings    OutsideWLSetting
			localSettings      LocalWLSetting
		}{
			{"With an invalid path to the topology file",
				"invalidPath", defaultInterval, WLAllNeighbours, WLLocalInfraNodes},
			{"With rescanning interval 0",
				pathToFile, 0, WLAllNeighbours, WLLocalInfraNodes},
			{"With no outside whitelisting and no local whitelisting",
				pathToFile, defaultInterval, NoOutsideWL, NoLocalWL},
		}

		for _, test := range tests {

			Convey(test.description, func() {

				filter, err := NewWhitelistFilter(test.pathToTopoFile, test.rescanningInterval, test.outsideSettings, test.localSettings)

				Convey("Should return an error", func() {
					So(err, ShouldNotBeNil)
				})

				Convey("Should return nil instead of a filter", func() {
					So(filter, ShouldBeNil)
				})
			})

		}
	})
}

func Test_NewWhitelistFilterFromStrings(t *testing.T) {

	Convey("Creating a whitelisting filter with the string", t, func() {

		tests := []struct {
			configString          []string
			pathToTopoFile        string
			rescanInterval        time.Duration
			outsideSettings       OutsideWLSetting
			localSettings         LocalWLSetting
			expectedNeighboursMap map[addr.IA]string
			expectedInfraNodeMap  map[string]string
		}{
			{[]string{outsideWL_flag, no_value, localWL_flag, AS_value},
				"./topology.json", defaultRescanningInterval,
				NoOutsideWL, WLLocalAS,
				emptyNeighboursMap, emptyInfraNodesMap},
			{[]string{rescanInterval_flag, "3", outsideWL_flag, ISD_value, localWL_flag, infra_value},
				"./topology.json", 3 * time.Minute,
				WLISD, WLLocalInfraNodes,
				emptyNeighboursMap, scannedInfraNodes},
			{[]string{rescanInterval_flag, "6000", outsideWL_flag, allNeighbours_value, localWL_flag, no_value},
				"./topology.json", 6000 * time.Minute,
				WLAllNeighbours, NoLocalWL,
				scannedNeighbours, emptyInfraNodesMap},
			{[]string{outsideWL_flag, upAndDownNeighbours_value},
				"./topology.json", defaultRescanningInterval,
				WLUpAndDownNeighbours, NoLocalWL,
				scannedUpAndDownNeighbours, emptyInfraNodesMap},
			{[]string{outsideWL_flag, coreNeighbours_value},
				"./topology.json", defaultRescanningInterval,
				WLCoreNeighbours, NoLocalWL,
				emptyNeighboursMap, emptyInfraNodesMap},
			{[]string{localWL_flag, infra_value},
				"./topology.json", defaultRescanningInterval,
				NoOutsideWL, WLLocalInfraNodes,
				emptyNeighboursMap, scannedInfraNodes},
			{[]string{path_flag, "./empty_topology.json", outsideWL_flag, allNeighbours_value, localWL_flag, infra_value},
				"./empty_topology.json", defaultRescanningInterval,
				WLAllNeighbours, WLLocalInfraNodes,
				emptyNeighboursMap, emptyInfraNodesMap},
		}

		for _, test := range tests {

			Convey(strings.Join(test.configString, " "), func() {

				filter, err := NewWhitelistFilterFromStrings(test.configString, ".")

				Convey("Should not return an error", func() {
					So(err, ShouldBeNil)
				})

				Convey(fmt.Sprintf("Should set path to %v", test.pathToTopoFile), func() {
					So(filter.pathToTopoFile, ShouldResemble, test.pathToTopoFile)
				})

				Convey(fmt.Sprintf("Should set the rescanning interval to %v", test.rescanInterval), func() {
					So(filter.rescanInterval, ShouldResemble, test.rescanInterval)
				})

				Convey(fmt.Sprintf("Should set outside settings to %v", test.outsideSettings.toString()), func() {
					So(filter.OutsideWLSetting, ShouldResemble, test.outsideSettings)
				})

				Convey(fmt.Sprintf("Should set local settings to %v", test.localSettings.toString()), func() {
					So(filter.LocalWLSetting, ShouldResemble, test.localSettings)
				})

				Convey("Should initialize the maps of the filter correctly", func() {
					So(filter.neighbouringNodes, ShouldResemble, test.expectedNeighboursMap)
					So(filter.localInfraNodes, ShouldResemble, test.expectedInfraNodeMap)
				})

			})
		}
	})

	Convey("Creating a whitelisting filter with the strings", t, func() {

		tests := []struct {
			configString []string
		}{
			{[]string{path_flag, "invalidPath", localWL_flag, AS_value}},  //invalid path to topo file
			{[]string{rescanInterval_flag, "-3", localWL_flag, AS_value}}, //invalid value for rescanning Interval
			{[]string{outsideWL_flag, no_value, localWL_flag, no_value}},  //no value for local and outside
			{[]string{outsideWL_flag, no_value}},
			{[]string{localWL_flag, no_value}},
			{[]string{}},
		}

		for _, test := range tests {

			Convey(strings.Join(test.configString, " "), func() {

				filter, err := NewWhitelistFilterFromStrings(test.configString, ".")

				Convey("Should return an error and nil instead of a filter", func() {
					So(err, ShouldNotBeNil)
					So(filter, ShouldBeNil)
				})
			})
		}
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

				filter, err := NewWhitelistFilter(pathToFileEmptyFile, defaultInterval, test.outsideSettings, WLLocalAS)

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

				filter, err := NewWhitelistFilter(pathToFileEmptyFile, defaultInterval, WLISD, test.localSettings)

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

		filter, _ := NewWhitelistFilter(pathToFileEmptyFile, defaultTestInterval, WLAllNeighbours, WLLocalInfraNodes)

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

		filter, _ := NewWhitelistFilter(pathToFileEmptyFile, defaultTestInterval, NoOutsideWL, WLLocalInfraNodes)

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

		filter, _ := NewWhitelistFilter(pathToFileEmptyFile, defaultTestInterval, WLAllNeighbours, NoLocalWL)

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

		filter, _ := NewWhitelistFilter(pathToFileEmptyFile, defaultTestInterval, WLISD, WLLocalAS)

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
