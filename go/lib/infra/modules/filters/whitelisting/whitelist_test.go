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
	minutesInADay = float64(1140)
	peer221, _    = addr.IAFromString("2-ff00:0:221")
	peer111, _    = addr.IAFromString("1-ff00:0:111")
	child212, _   = addr.IAFromString("2-ff00:0:212")
	child222, _   = addr.IAFromString("2-ff00:0:222")
	parent210, _  = addr.IAFromString("2-ff00:0:210")

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

	localScionAddr            = snet.SCIONAddress{IA: localIA, Host: anyHostAddr}
	localInfraNodeScionAddr   = snet.SCIONAddress{IA: localIA, Host: infraHostAddr}
	localISDNeighbourAddr     = snet.SCIONAddress{IA: peer221, Host: anyHostAddr}
	localISDNonNeighbourAddr  = snet.SCIONAddress{IA: nonNeighbourFromLocalISD, Host: anyHostAddr}
	remoteISDNonNeighbourAddr = snet.SCIONAddress{IA: nonNeighbourFromRemoteISD, Host: anyHostAddr}
	remoteISDNeighbourAddr    = snet.SCIONAddress{IA: peer111, Host: anyHostAddr}

	scannedNeighbours          = map[addr.IA]string{peer221: "", peer111: "", child212: "", child222: "", parent210: ""}
	scannedUpAndDownNeighbours = map[addr.IA]string{child212: "", child222: "", parent210: ""}
	emptyNeighboursMap         = map[addr.IA]string{}
	scannedInfraNodes          = map[string]string{"127.0.0.209": "", "127.0.0.210": "", "127.0.0.211": "", "127.0.0.212": ""}
	emptyInfraNodesMap         = map[string]string{}

	oldNeighbours = map[addr.IA]string{oldPeer115: "", oldChild225: "", oldParent215: "", oldCore233: ""}
	oldInfraNodes = map[string]string{"127.0.0.001": "", "127.0.0.002": ""}
)

func Test_NewWhitelistFilter(t *testing.T) {

	Convey("Creating a new filter", t, func() {

		Convey("With valid settings", func() {

			filter, err := NewWhitelistFilter(pathToFile, minutesInADay, WLAllNeighbours, WLLocalInfraNodes)

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

		tests := []struct {
			description        string
			pathToTopoFile     string
			rescanningInterval float64
			outsideSettings    OutsideWLSetting
			localSettings      LocalWLSetting
		}{
			{"With an invalid path to the topology file",
				"invalidPath", minutesInADay, WLAllNeighbours, WLLocalInfraNodes},
			{"With a negative rescanning interval",
				pathToFile, float64(-3), WLAllNeighbours, WLLocalInfraNodes},
			{"With no outside whitelisting and no local whitelisting",
				pathToFile, minutesInADay, NoOutsideWL, NoLocalWL},
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

				filter, err := NewWhitelistFilter(pathToFile, minutesInADay, test.outsideSettings, WLLocalAS)

				err = filter.rescanTopoFile()

				Convey("Should not create an error", func() {
					So(err, ShouldBeNil)
				})

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

				filter, err := NewWhitelistFilter(pathToFile, minutesInADay, WLISD, test.localSettings)
				err = filter.rescanTopoFile()

				Convey("Should not create an error", func() {
					So(err, ShouldBeNil)
				})

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

func Test_rescanTopoFileIfNecessary(t *testing.T) {

	Convey("A rescanTopoFileIfNecessary call on a newly created filter", t, func() {

		filter, _ := NewWhitelistFilter(pathToFile, 60, WLAllNeighbours, WLLocalInfraNodes)

		Convey("With empty node maps", func() {
			So(filter.neighbouringNodes, ShouldBeEmpty)
			So(filter.localInfraNodes, ShouldBeEmpty)
		})

		filter.rescanTopoFileIfNecessary()

		Convey("Should fill the neighbours and infra node maps", func() {
			So(filter.neighbouringNodes, ShouldResemble, scannedNeighbours)
			So(filter.localInfraNodes, ShouldResemble, scannedInfraNodes)
		})

		Convey("Should set the lastScan field to somewhere in the last 10 seconds", func() {
			So(filter.lastScan, ShouldHappenWithin, time.Second*10, time.Now())
		})
	})

	Convey("A rescanTopoFileIfNecessary call on an existing filter", t, func() {

		filter := &WhitelistFilter{
			pathToTopoFile:    pathToFile,
			rescanInterval:    60,
			lastScan:          time.Now().Add(-time.Minute * 61),
			localIA:           localIA,
			neighbouringNodes: oldNeighbours,
			localInfraNodes:   oldInfraNodes,
			OutsideWLSetting:  WLAllNeighbours,
			LocalWLSetting:    WLLocalInfraNodes,
		}

		Convey("With maps filled with old values", func() {
			So(filter.neighbouringNodes, ShouldResemble, oldNeighbours)
			So(filter.localInfraNodes, ShouldResemble, oldInfraNodes)
		})

		Convey("And a lastScan longer ago than the rescan interval", func() {
			So(time.Since(filter.lastScan).Minutes(), ShouldBeGreaterThan, filter.rescanInterval)
		})

		filter.rescanTopoFileIfNecessary()

		Convey("Should refill the neighbours and infra nodes maps with new values", func() {
			So(filter.neighbouringNodes, ShouldResemble, scannedNeighbours)
			So(filter.localInfraNodes, ShouldResemble, scannedInfraNodes)
		})

		Convey("Should set the lastScan field to be somewhere in the last 10 seconds", func() {
			So(filter.lastScan, ShouldHappenWithin, time.Second*10, time.Now())
		})
	})

	Convey("A rescanTopoFileIfNecessary call on an existing filter", t, func() {

		filter := &WhitelistFilter{
			pathToTopoFile:    "invalidPath",
			rescanInterval:    60,
			lastScan:          time.Now().Add(-time.Minute * 61),
			localIA:           localIA,
			neighbouringNodes: oldNeighbours,
			localInfraNodes:   oldInfraNodes,
			OutsideWLSetting:  WLAllNeighbours,
			LocalWLSetting:    WLLocalInfraNodes,
		}

		Convey("With maps filled with old values", func() {
			So(filter.neighbouringNodes, ShouldResemble, oldNeighbours)
			So(filter.localInfraNodes, ShouldResemble, oldInfraNodes)
		})

		Convey("And a lastScan longer ago than the rescan interval, but an invalid topology file path", func() {
			So(time.Since(filter.lastScan).Minutes(), ShouldBeGreaterThan, filter.rescanInterval)
		})

		lastScan := filter.lastScan
		filter.rescanTopoFileIfNecessary()

		Convey("Should not change the values of the node maps", func() {
			So(filter.neighbouringNodes, ShouldResemble, oldNeighbours)
			So(filter.localInfraNodes, ShouldResemble, oldInfraNodes)
		})

		Convey("Should not change the value of the lastScan field", func() {
			So(filter.lastScan, ShouldResemble, lastScan)
		})
	})

	Convey("A rescanTopoFileIfNecessary call on an existing filter", t, func() {

		filter := &WhitelistFilter{
			pathToTopoFile:    pathToFile,
			rescanInterval:    60,
			lastScan:          time.Now(),
			localIA:           localIA,
			neighbouringNodes: oldNeighbours,
			localInfraNodes:   oldInfraNodes,
			OutsideWLSetting:  WLAllNeighbours,
			LocalWLSetting:    WLLocalInfraNodes,
		}

		Convey("With maps filled with old values", func() {
			So(filter.neighbouringNodes, ShouldResemble, oldNeighbours)
			So(filter.localInfraNodes, ShouldResemble, oldInfraNodes)
		})

		Convey("And a lastScan not longer ago than the rescan interval", func() {
			So(time.Since(filter.lastScan).Minutes(), ShouldBeLessThanOrEqualTo, filter.rescanInterval)
		})

		lastScan := filter.lastScan
		filter.rescanTopoFileIfNecessary()

		Convey("Should not change the values of the node maps", func() {
			So(filter.neighbouringNodes, ShouldResemble, oldNeighbours)
			So(filter.localInfraNodes, ShouldResemble, oldInfraNodes)
		})

		Convey("Should not change the value of the lastScan field", func() {
			So(filter.lastScan, ShouldResemble, lastScan)
		})
	})

}

func Test_filterDependingOnInfraNodeWL(t *testing.T) {

	filter := &WhitelistFilter{
		pathToTopoFile:    pathToFile,
		rescanInterval:    60,
		lastScan:          time.Now(),
		localIA:           localIA,
		neighbouringNodes: scannedNeighbours,
		localInfraNodes:   scannedInfraNodes,
		OutsideWLSetting:  NoOutsideWL,
		LocalWLSetting:    WLLocalInfraNodes,
	}

	Convey(fmt.Sprintf("A filter that whitelists local infra nodes"), t, func() {

		Convey("Should accept requests from local infra nodes", func() {

			result, err := filter.filterDependingOnInfraNodeWL(localInfraNodeScionAddr)

			So(result, ShouldResemble, filters.FilterAccept)
			So(err, ShouldBeNil)
		})

		Convey("Should drop requests from non infra nodes", func() {

			result, err := filter.filterDependingOnInfraNodeWL(localScionAddr)

			So(result, ShouldResemble, filters.FilterDrop)
			So(err, ShouldBeNil)
		})
	})
}

func Test_FilterAddr(t *testing.T) {

	Convey("Filtering on a filter with local settings", t, func() {

		infraPacket := packetFrom(localInfraNodeScionAddr)
		nonInfraPacket := packetFrom(localScionAddr)

		tests := []struct {
			localSettings     LocalWLSetting
			isError           bool
			resultForInfra    filters.FilterResult
			resultForNonInfra filters.FilterResult
		}{
			{WLLocalAS, false,
				filters.FilterAccept, filters.FilterAccept},
			{NoLocalWL, false,
				filters.FilterDrop, filters.FilterDrop},
			{WLLocalInfraNodes, false,
				filters.FilterAccept, filters.FilterDrop},
			{LocalWLSetting(5), true,
				filters.FilterError, filters.FilterError},
		}

		for _, test := range tests {

			Convey(test.localSettings.toString(), func() {

				filter := &WhitelistFilter{
					pathToTopoFile:    pathToFile,
					rescanInterval:    60,
					lastScan:          time.Now(),
					localIA:           localIA,
					neighbouringNodes: scannedNeighbours,
					localInfraNodes:   scannedInfraNodes,
					OutsideWLSetting:  NoOutsideWL,
					LocalWLSetting:    test.localSettings,
				}

				Convey(fmt.Sprintf("Should result in %v for infra packets", test.resultForInfra.ToString()), func() {

					result, err := filter.FilterPacket(infraPacket)

					So(result, ShouldResemble, test.resultForInfra)
					if test.isError {
						So(err, ShouldNotBeNil)
					} else {
						So(err, ShouldBeNil)
					}
				})

				Convey(fmt.Sprintf("Should result in %v for non infra packets", test.resultForNonInfra.ToString()), func() {

					result, err := filter.FilterPacket(nonInfraPacket)

					So(result, ShouldResemble, test.resultForNonInfra)
					if test.isError {
						So(err, ShouldNotBeNil)
					} else {
						So(err, ShouldBeNil)
					}
				})
			})
		}
	})

	Convey("Filtering on a filter with outside settings", t, func() {

		remoteISDNonNeighbourPacket := packetFrom(remoteISDNonNeighbourAddr)
		remoteISDNeighbourPacket := packetFrom(remoteISDNeighbourAddr)
		localISDNonNeighbourPacket := packetFrom(localISDNonNeighbourAddr)
		localISDNeighbourPacket := packetFrom(localISDNeighbourAddr)

		tests := []struct {
			outsideSettings                OutsideWLSetting
			isError                        bool
			resultForRemoteISDNonNeighbour filters.FilterResult
			resultForRemoteISDNeighbour    filters.FilterResult
			resultForLocalISDNonNeighbour  filters.FilterResult
			resultForLocalISDNeighbour     filters.FilterResult
		}{
			{NoOutsideWL, false,
				filters.FilterDrop, filters.FilterDrop,
				filters.FilterDrop, filters.FilterDrop},
			{WLISD, false,
				filters.FilterDrop, filters.FilterDrop,
				filters.FilterAccept, filters.FilterAccept},
			{WLAllNeighbours, false,
				filters.FilterDrop, filters.FilterAccept,
				filters.FilterDrop, filters.FilterAccept},
			{OutsideWLSetting(7), true,
				filters.FilterError, filters.FilterError,
				filters.FilterError, filters.FilterError},
		}

		for _, test := range tests {

			Convey(test.outsideSettings.toString(), func() {

				filter := &WhitelistFilter{
					pathToTopoFile:    pathToFile,
					rescanInterval:    60,
					lastScan:          time.Now(),
					localIA:           localIA,
					neighbouringNodes: scannedNeighbours,
					localInfraNodes:   scannedInfraNodes,
					OutsideWLSetting:  test.outsideSettings,
					LocalWLSetting:    NoLocalWL,
				}

				Convey(fmt.Sprintf("Should result in %v for a packet from a non neighbour from a remote ISD",
					test.resultForRemoteISDNonNeighbour.ToString()), func() {

					result, err := filter.FilterPacket(remoteISDNonNeighbourPacket)

					So(result, ShouldResemble, test.resultForRemoteISDNonNeighbour)
					if test.isError {
						So(err, ShouldNotBeNil)
					} else {
						So(err, ShouldBeNil)
					}
				})

				Convey(fmt.Sprintf("Should result in %v for a packet from a neighbour from a remote ISD",
					test.resultForRemoteISDNeighbour.ToString()), func() {

					result, err := filter.FilterPacket(remoteISDNeighbourPacket)

					So(result, ShouldResemble, test.resultForRemoteISDNeighbour)
					if test.isError {
						So(err, ShouldNotBeNil)
					} else {
						So(err, ShouldBeNil)
					}
				})

				Convey(fmt.Sprintf("Should result in %v for a packet from a non neighbour from a local ISD",
					test.resultForLocalISDNonNeighbour.ToString()), func() {

					result, err := filter.FilterPacket(localISDNonNeighbourPacket)

					So(result, ShouldResemble, test.resultForLocalISDNonNeighbour)
					if test.isError {
						So(err, ShouldNotBeNil)
					} else {
						So(err, ShouldBeNil)
					}
				})

				Convey(fmt.Sprintf("Should result in %v for a packet from a neighbour from a local ISD",
					test.resultForLocalISDNeighbour.ToString()), func() {

					result, err := filter.FilterPacket(localISDNeighbourPacket)

					So(result, ShouldResemble, test.resultForLocalISDNeighbour)
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

func packetFrom(addr snet.SCIONAddress) *snet.SCIONPacket {
	return &snet.SCIONPacket{
		Bytes: nil,
		SCIONPacketInfo: snet.SCIONPacketInfo{
			Source: addr,
		},
	}
}
