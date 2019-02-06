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

package filters

import (
	"fmt"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
	"time"

	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

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

	pathToFile   = "./test_topology.json"
	localAddr, _ = snet.AddrFromString("2-ff00:0:211,[127.0.0.250]:1234")

	scannedNeighbours          = map[addr.IA]string{peer221: "", peer111: "", child212: "", child222: "", parent210: ""}
	scannedUpAndDownNeighbours = map[addr.IA]string{child212: "", child222: "", parent210: ""}

	oldNeighbours          = map[addr.IA]string{oldPeer115: "", oldChild225: "", oldParent215: "", oldCore233: ""}
	oldUpAndDownNeighbours = map[addr.IA]string{oldChild225: "", oldParent215: ""}
	oldCoreNeighbours      = map[addr.IA]string{oldCore233: ""}
)

func Test_NewWhitelistFilter(t *testing.T) {

	Convey("Creating a new filter", t, func() {

		filter, err := NewWhitelistFilter(pathToFile, 0, WLAllNeighbours, WLLocalInfraNodes)

		Convey("Should not create an error", func() {
			So(err, ShouldBeNil)
		})

		Convey("Should set the local IA address of the filter", func() {
			So(filter.localIA, ShouldResemble, localAddr.IA)
		})

		Convey("Should not fill the neighbouring nodes map of the filter", func() {
			So(filter.neighbouringNodes, ShouldBeEmpty)
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
				map[addr.IA]string{}, "core neighbours"},
			{NoOutsideWL, "NoOutsideWL",
				map[addr.IA]string{}, "no neighbours"},
			{WLISD, "WLISD",
				map[addr.IA]string{}, "no neighbours"},
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
	})
}

func Test_FilterAddr(t *testing.T) {

	Convey("The first FilterAddr call on a new filter", t, func() {

		filter, _ := NewWhitelistFilter(pathToFile, 0, WLAllNeighbours, WLLocalInfraNodes)

		Convey("With a previously empty neighbouring node map", func() {
			So(filter.neighbouringNodes, ShouldBeEmpty)
		})

		_, _ = filter.FilterAddr(localAddr)

		Convey("Should rescan the topology file and fill the neighbours map", func() {
			So(filter.neighbouringNodes, ShouldResemble, scannedNeighbours)
		})
	})

	Convey("A FilterAddr call on a filter with the last scan longer ago than the rescanning interval", t, func() {

		filter := &WhitelistFilter{
			pathToFile,
			360,
			time.Now().Add(-time.Second * 361),
			localAddr.IA,
			oldNeighbours,
			map[addr.IA]string{},
			WLAllNeighbours,
			WLLocalInfraNodes,
		}

		Convey("With a previously old neighbouring node map", func() {
			So(filter.neighbouringNodes, ShouldResemble, oldNeighbours)
		})

		_, _ = filter.FilterAddr(localAddr)

		Convey("Should rescan the topology file and refill the neighbours map", func() {
			So(filter.neighbouringNodes, ShouldResemble, scannedNeighbours)
		})
	})

	Convey("A FilterAddr call on a filter with a recent scan", t, func() {

		filter := &WhitelistFilter{
			pathToFile,
			360,
			time.Now(),
			localAddr.IA,
			oldNeighbours,
			map[addr.IA]string{},
			WLAllNeighbours,
			WLLocalInfraNodes,
		}

		Convey("With a previous neighbours map", func() {
			So(filter.neighbouringNodes, ShouldResemble, oldNeighbours)
		})

		_, _ = filter.FilterAddr(localAddr)

		Convey("Should keep the same neighbours map", func() {
			So(filter.neighbouringNodes, ShouldResemble, oldNeighbours)
		})
	})

	Convey("Filtering a local address", t, func() {

		tests := []struct {
			localSettings LocalWLSetting
			settingsName  string
			result        FilterResult
			resultName    string
			isError       bool
		}{
			{WLLocalAS, "WLLocalAS",
				FilterAccept, "Ack of the packet", false},
			{NoLocalWL, "NoLocalWL",
				FilterDrop, "Drop of the packet", false},
			//{WLLocalInfraNodes,"WLLocalInfraNodes",
			//	FilterAccept,"", false},
			{LocalWLSetting(5), "an invalid Setting",
				FilterError, "a Filtering error", true},
		}

		for _, test := range tests {

			Convey(fmt.Sprintf("With local filtering set to %v", test.settingsName), func() {

				filter := &WhitelistFilter{
					pathToFile,
					360,
					time.Now(),
					localAddr.IA,
					oldNeighbours,
					map[addr.IA]string{},
					WLAllNeighbours,
					test.localSettings,
				}

				result, err := filter.FilterAddr(localAddr)

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

	//TODO: add filtering test for remote addresses
}
