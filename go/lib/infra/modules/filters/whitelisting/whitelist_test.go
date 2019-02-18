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
	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/snet"
)

// This test uses the test_topology.json file in the same folder.
// It is a copy of the topology.json from ASff00_0_211 of the default topology.
var (
	peer221, _   = addr.IAFromString("2-ff00:0:221")
	peer111, _   = addr.IAFromString("1-ff00:0:111")
	child212, _  = addr.IAFromString("2-ff00:0:212")
	child222, _  = addr.IAFromString("2-ff00:0:222")
	parent210, _ = addr.IAFromString("2-ff00:0:210")

	oldPeer115, _   = addr.IAFromString("1-ff00:0:115")
	oldChild225, _  = addr.IAFromString("2-ff00:0:225")
	oldParent215, _ = addr.IAFromString("2-ff00:0:215")
	oldCore233, _   = addr.IAFromString("2-ff00:0:233")

	nonNeighbourFromLocalISD, _  = addr.IAFromString("2-ff00:0:201")
	nonNeighbourFromRemoteISD, _ = addr.IAFromString("1-ff00:0:100")

	localIA, _ = addr.IAFromString("2-ff00:0:211")

	anyHostAddr   = addr.HostFromIPStr("127.0.0.250")
	infraHostAddr = addr.HostFromIPStr("127.0.0.209")

	pathToFile = "./test_topology.json"

	localScionAddr             = snet.SCIONAddress{IA: localIA, Host: anyHostAddr}
	localInfraNodeScionAddr    = snet.SCIONAddress{IA: localIA, Host: infraHostAddr}
	localISDNeighbourAddr      = snet.SCIONAddress{IA: peer221, Host: anyHostAddr}
	localISDButNoNeighbourAddr = snet.SCIONAddress{IA: nonNeighbourFromLocalISD, Host: anyHostAddr}
	remoteISDAddr              = snet.SCIONAddress{IA: nonNeighbourFromRemoteISD, Host: anyHostAddr}
	remoteISDButNeighbourAddr  = snet.SCIONAddress{IA: peer111, Host: anyHostAddr}

	scannedNeighbours          = map[addr.IA]string{peer221: "", peer111: "", child212: "", child222: "", parent210: ""}
	scannedUpAndDownNeighbours = map[addr.IA]string{child212: "", child222: "", parent210: ""}
	emptyNeighboursMap         = map[addr.IA]string{}
	scannedInfraNodes          = map[string]string{"127.0.0.209": "", "127.0.0.210": "", "127.0.0.211": "", "127.0.0.212": ""}
	emptyInfraNodesMap         = map[string]string{}

	oldNeighbours          = map[addr.IA]string{oldPeer115: "", oldChild225: "", oldParent215: "", oldCore233: ""}
	oldUpAndDownNeighbours = map[addr.IA]string{oldChild225: "", oldParent215: ""}
	oldCoreNeighbours      = map[addr.IA]string{oldCore233: ""}
)

func Test_NewWhitelistFilter(t *testing.T) {

	Convey("Creating a new filter with a valid path to the topology file", t, func() {

		filter, err := NewWhitelistFilter(pathToFile, 0, WLAllNeighbours, WLLocalInfraNodes)

		Convey("Should not return an error", func() {
			So(err, ShouldBeNil)
		})

		Convey("Should set the local IA address of the filter", func() {
			So(filter.localIA, ShouldResemble, localIA)
		})

		Convey("Should not fill any maps of the filter", func() {
			So(filter.neighbouringNodes, ShouldBeEmpty)
			So(filter.localInfraNodes, ShouldBeEmpty)
		})
	})

	Convey("Creating a new filter with an invalid path to the topology file", t, func() {

		filter, err := NewWhitelistFilter("invalidPath", 0, WLAllNeighbours, WLLocalInfraNodes)

		Convey("Should return an error", func() {
			So(err, ShouldNotBeNil)
		})

		Convey("Should not set the local IA address of the filter", func() {
			So(filter.localIA, ShouldBeZeroValue)
		})

		Convey("Should not fill any maps of the filter", func() {
			So(filter.neighbouringNodes, ShouldBeEmpty)
			So(filter.localInfraNodes, ShouldBeEmpty)
		})
	})
}

func Test_rescanTopoFile(t *testing.T) {

	Convey("Rescanning the topology file", t, func() {

		tests := []struct {
			outsideSettings OutsideWLSetting
			settingsName    string
			neighboursMap   map[addr.IA]string
			contentName     string
		}{

			{WLAllNeighbours, "WLAllNeighbours",
				scannedNeighbours, "all neighbours"},
			{WLUpAndDownNeighbours, "WLUpAndDownNeighbours",
				scannedUpAndDownNeighbours, "up and downstream neighbours"},
			{WLCoreNeighbours, "WLCoreNeighbours",
				emptyNeighboursMap, "core neighbours"},
			{NoOutsideWL, "NoOutsideWL",
				emptyNeighboursMap, "no neighbours"},
			{WLISD, "WLISD",
				emptyNeighboursMap, "no neighbours"},
		}

		for _, test := range tests {

			Convey(fmt.Sprintf("With Outside settings %q and no local Whitelisting", test.settingsName), func() {

				filter, err := NewWhitelistFilter(pathToFile, 0, test.outsideSettings, NoLocalWL)

				Convey("Initializing a new Filter should not create an error", func() {
					So(err, ShouldBeNil)
				})

				err = filter.rescanTopoFile()

				Convey("Rescanning the topology file should not create an error", func() {
					So(err, ShouldBeNil)
				})

				Convey(fmt.Sprintf("The map of neighbouring nodes should be filled with %v", test.contentName), func() {
					So(filter.neighbouringNodes, ShouldResemble, test.neighboursMap)
				})
			})
		}

		localTests := []struct {
			localSettings     LocalWLSetting
			settingsName      string
			localInfraNodeMap map[string]string
			contentName       string
		}{

			{WLLocalAS, "WLLocalAS",
				emptyInfraNodesMap, "nothing"},
			{WLLocalInfraNodes, "WLLocalInfraNodes",
				scannedInfraNodes, "the local infra nodes IPs"},
			{NoLocalWL, "NoLocalWL",
				emptyInfraNodesMap, "nothing"},
		}

		for _, test := range localTests {

			Convey(fmt.Sprintf("With local settings %q and no outside Whitelisting", test.settingsName), func() {

				filter, err := NewWhitelistFilter(pathToFile, 0, NoOutsideWL, test.localSettings)

				Convey("Initializing a new Filter should not create an error", func() {
					So(err, ShouldBeNil)
				})

				err = filter.rescanTopoFile()

				Convey("Rescanning the topology file should not create an error", func() {
					So(err, ShouldBeNil)
				})

				Convey(fmt.Sprintf("The map of neighbouring nodes should contain %v", test.contentName), func() {
					So(filter.localInfraNodes, ShouldResemble, test.localInfraNodeMap)
				})
			})
		}

	})
}

func Test_rescanTopoFileIfNecessary(t *testing.T) {

	Convey("A newly created filter", t, func() {

		filter, _ := NewWhitelistFilter(pathToFile, 360, WLAllNeighbours, WLLocalInfraNodes)

		Convey("Should have empty node maps", func() {
			So(filter.neighbouringNodes, ShouldBeEmpty)
			So(filter.localInfraNodes, ShouldBeEmpty)
		})

		filter.rescanTopoFileIfNecessary()

		Convey("Should rescan the topology file and fill the neighbours map on a rescanTopoFileIfNecessary call", func() {
			So(filter.neighbouringNodes, ShouldResemble, scannedNeighbours)
			So(filter.localInfraNodes, ShouldResemble, scannedInfraNodes)
		})

		Convey("Should have the lastScan field set to be somewhere in the last 10 seconds", func() {
			So(filter.lastScan, ShouldHappenWithin, time.Second*10, time.Now())
		})
	})

	Convey("An existing filter", t, func() {

		filter := &WhitelistFilter{
			pathToTopoFile:    pathToFile,
			rescanInterval:    360,
			lastScan:          time.Now().Add(-time.Second * 361),
			localIA:           localIA,
			neighbouringNodes: oldNeighbours,
			localInfraNodes:   emptyInfraNodesMap,
			OutsideWLSetting:  WLAllNeighbours,
			LocalWLSetting:    WLLocalInfraNodes,
		}

		Convey("With a previously old neighbouring node map", func() {
			So(filter.neighbouringNodes, ShouldResemble, oldNeighbours)
		})

		Convey("And a lastScan longer ago than the rescan interval", func() {
			So(time.Since(filter.lastScan).Seconds(), ShouldBeGreaterThan, filter.rescanInterval)
		})

		filter.rescanTopoFileIfNecessary()

		Convey("Should rescan the topology file and refill the neighbours map on a rescanTopoFileIfNecessary call", func() {
			So(filter.neighbouringNodes, ShouldResemble, scannedNeighbours)
			So(filter.localInfraNodes, ShouldResemble, scannedInfraNodes)
		})

		Convey("Should have the lastScan field set to be somewhere in the last 10 seconds", func() {
			So(filter.lastScan, ShouldHappenWithin, time.Second*10, time.Now())
		})
	})

	Convey("An existing filter", t, func() {

		filter := &WhitelistFilter{
			pathToTopoFile:    "invalidPath",
			rescanInterval:    360,
			lastScan:          time.Now().Add(-time.Second * 361),
			localIA:           localIA,
			neighbouringNodes: oldNeighbours,
			localInfraNodes:   emptyInfraNodesMap,
			OutsideWLSetting:  WLAllNeighbours,
			LocalWLSetting:    WLLocalInfraNodes,
		}

		Convey("With a previously old neighbouring node map", func() {
			So(filter.neighbouringNodes, ShouldResemble, oldNeighbours)
		})

		Convey("And a lastScan longer ago than the rescan interval, but an invalid topology file path", func() {
			So(time.Since(filter.lastScan).Seconds(), ShouldBeGreaterThan, filter.rescanInterval)
		})

		lastScan := filter.lastScan
		filter.rescanTopoFileIfNecessary()

		Convey("Should keep the same node maps on a rescanTopoFileIfNecessary call", func() {
			So(filter.neighbouringNodes, ShouldResemble, oldNeighbours)
			So(filter.localInfraNodes, ShouldResemble, emptyInfraNodesMap)
		})

		Convey("And have the same value for the lastScan field as before the call", func() {
			So(filter.lastScan, ShouldResemble, lastScan)
		})
	})

	Convey("An existing filter", t, func() {

		filter := &WhitelistFilter{
			pathToTopoFile:    pathToFile,
			rescanInterval:    360,
			lastScan:          time.Now(),
			localIA:           localIA,
			neighbouringNodes: oldNeighbours,
			localInfraNodes:   emptyInfraNodesMap,
			OutsideWLSetting:  WLAllNeighbours,
			LocalWLSetting:    WLLocalInfraNodes,
		}

		Convey("With a previous neighbours map", func() {
			So(filter.neighbouringNodes, ShouldResemble, oldNeighbours)
		})

		Convey("And a lastScan not longer ago than the rescan interval", func() {
			So(time.Since(filter.lastScan).Seconds(), ShouldBeLessThanOrEqualTo, filter.rescanInterval)
		})

		lastScan := filter.lastScan
		filter.rescanTopoFileIfNecessary()

		Convey("Should keep the same node maps on a rescanTopoFileIfNecessary call", func() {
			So(filter.neighbouringNodes, ShouldResemble, oldNeighbours)
			So(filter.localInfraNodes, ShouldResemble, emptyInfraNodesMap)
		})

		Convey("And have the same value for the lastScan field as before the call", func() {
			So(filter.lastScan, ShouldResemble, lastScan)
		})
	})

}

func Test_filterDependingOnInfraNodeWL(t *testing.T) {

	tests := []struct {
		localAddress snet.SCIONAddress
		addressName  string
		result       filters.FilterResult
		resultName   string
	}{
		{localInfraNodeScionAddr, "an infrastructure",
			filters.FilterAccept, "Ack of the packet"},
		{localScionAddr, "a non-infrastructure",
			filters.FilterDrop, "Drop of the packet"},
	}

	filter := &WhitelistFilter{
		pathToTopoFile:    pathToFile,
		rescanInterval:    360,
		lastScan:          time.Now(),
		localIA:           localIA,
		neighbouringNodes: oldNeighbours,
		localInfraNodes:   scannedInfraNodes,
		OutsideWLSetting:  NoOutsideWL,
		LocalWLSetting:    WLLocalInfraNodes,
	}

	Convey(fmt.Sprintf("With local filtering set to WLLocalInfraNodes"), t, func() {

		for _, test := range tests {

			result, err := filter.filterDependingOnInfraNodeWL(test.localAddress)

			Convey(fmt.Sprintf("Filtering %v address should result in %v", test.addressName, test.resultName), func() {
				So(result, ShouldResemble, test.result)
				So(err, ShouldBeNil)
			})
		}
	})
}

func Test_FilterAddr(t *testing.T) {

	Convey("Filtering a local address", t, func() {

		tests := []struct {
			localSettings   LocalWLSetting
			settingsName    string
			result          filters.FilterResult
			resultName      string
			isError         bool
			infraNodesMap   map[string]string
			addressToFilter snet.SCIONAddress
			addressName     string
		}{
			{WLLocalAS, "WLLocalAS",
				filters.FilterAccept, "Ack of the packet",
				false, emptyInfraNodesMap,
				localScionAddr, "a non-infrastructure"},
			{NoLocalWL, "NoLocalWL",
				filters.FilterDrop, "Drop of the packet",
				false, emptyInfraNodesMap,
				localInfraNodeScionAddr, "an infrastructure"},
			{WLLocalInfraNodes, "WLLocalInfraNodes",
				filters.FilterAccept, "Ack of the packet",
				false, scannedInfraNodes,
				localInfraNodeScionAddr, "an infrastructure"},
			{WLLocalInfraNodes, "WLLocalInfraNodes",
				filters.FilterDrop, "Drop of the packet",
				false, scannedInfraNodes,
				localScionAddr, "a non-infrastructure"},
			{LocalWLSetting(5), "an invalid Setting",
				filters.FilterError, "a Filtering error",
				true, emptyInfraNodesMap,
				localInfraNodeScionAddr, "an infrastructure"},
		}

		for _, test := range tests {

			Convey(fmt.Sprintf("With local filtering set to %v and %v address", test.settingsName, test.addressName), func() {

				filter := &WhitelistFilter{
					pathToTopoFile:    pathToFile,
					rescanInterval:    360,
					lastScan:          time.Now(),
					localIA:           localIA,
					neighbouringNodes: oldNeighbours,
					localInfraNodes:   test.infraNodesMap,
					OutsideWLSetting:  NoOutsideWL,
					LocalWLSetting:    test.localSettings,
				}

				result, err := filter.FilterPacket(
					&snet.SCIONPacket{
						Bytes: nil,
						SCIONPacketInfo: snet.SCIONPacketInfo{
							Source: test.addressToFilter,
						},
					})

				Convey(fmt.Sprintf("Should result in %v", test.resultName), func() {
					So(result, ShouldResemble, test.result)
					if test.isError {
						So(err, ShouldNotBeNil)
					} else {
						So(err, ShouldBeNil)
					}
				})
			})
		}
	})

	Convey("Filtering a remote address", t, func() {

		tests := []struct {
			outsideSettings OutsideWLSetting
			settingsName    string
			result          filters.FilterResult
			resultName      string
			isError         bool
			addressToFilter snet.SCIONAddress
			addressName     string
		}{
			{NoOutsideWL, "NoOutsideWL",
				filters.FilterDrop, "drop of the packet",
				false, localISDNeighbourAddr, "the local ISD"},
			{WLISD, "WLISD",
				filters.FilterAccept, "ack of the packet",
				false, localISDButNoNeighbourAddr, "the local ISD"},
			{WLISD, "WLISD",
				filters.FilterDrop, "drop of the packet",
				false, remoteISDAddr, "a remote ISD"},
			{WLAllNeighbours, "WLAllNeighbours",
				filters.FilterAccept, "ack of the packet",
				false, remoteISDButNeighbourAddr, "a neighbour being in a remote ISD"},
			{WLAllNeighbours, "WLAllNeighbours",
				filters.FilterDrop, "drop of the packet",
				false, localISDButNoNeighbourAddr, "a non-neighbour of the local ISD"},
			{OutsideWLSetting(7), "an invalid setting",
				filters.FilterError, "a filter error",
				true, localISDNeighbourAddr, "a neighbour of the local ISD"},
		}

		for _, test := range tests {

			Convey(fmt.Sprintf("With outside filtering set to %v and the address being from %v", test.settingsName, test.addressName), func() {

				filter := &WhitelistFilter{
					pathToTopoFile:    pathToFile,
					rescanInterval:    360,
					lastScan:          time.Now(),
					localIA:           localIA,
					neighbouringNodes: scannedNeighbours,
					localInfraNodes:   scannedInfraNodes,
					OutsideWLSetting:  test.outsideSettings,
					LocalWLSetting:    NoLocalWL,
				}

				result, err := filter.FilterPacket(
					&snet.SCIONPacket{
						Bytes: nil,
						SCIONPacketInfo: snet.SCIONPacketInfo{
							Source: test.addressToFilter,
						},
					})

				Convey(fmt.Sprintf("Should result in %v", test.resultName), func() {
					So(result, ShouldResemble, test.result)
					if test.isError {
						So(err, ShouldNotBeNil)
					} else {
						So(err, ShouldBeNil)
					}
				})
			})
		}
	})
}
