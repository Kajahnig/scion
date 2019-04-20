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

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/snet"
)

var (
	nonNeighbourFromLocalISD, _  = addr.IAFromString("2-ff00:0:201")
	nonNeighbourFromRemoteISD, _ = addr.IAFromString("1-ff00:0:100")

	anyHostAddr   = addr.HostFromIPStr("127.0.0.250")
	infraHostAddr = addr.HostFromIPStr("127.0.0.209")

	localScionAddr            = snet.SCIONAddress{IA: localIA, Host: anyHostAddr}
	localInfraNodeScionAddr   = snet.SCIONAddress{IA: localIA, Host: infraHostAddr}
	localISDNeighbourAddr     = snet.SCIONAddress{IA: peer221, Host: anyHostAddr}
	localISDNonNeighbourAddr  = snet.SCIONAddress{IA: nonNeighbourFromLocalISD, Host: anyHostAddr}
	remoteISDNonNeighbourAddr = snet.SCIONAddress{IA: nonNeighbourFromRemoteISD, Host: anyHostAddr}
	remoteISDNeighbourAddr    = snet.SCIONAddress{IA: peer111, Host: anyHostAddr}
)

func Test_filterDependingOnInfraNodeWL(t *testing.T) {

	filter := WhitelistFilterWithSettings(NoOutsideWL, WLLocalInfraNodes)

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

				filter := WhitelistFilterWithSettings(NoOutsideWL, test.localSettings)

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

				filter := WhitelistFilterWithSettings(test.outsideSettings, NoLocalWL)

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

func WhitelistFilterWithSettings(outsideSetting OutsideWLSetting, localSetting LocalWLSetting) *WhitelistFilter {
	return &WhitelistFilter{
		pathToTopoFile:    pathToFile,
		rescanInterval:    defaultRescanningInterval,
		localIA:           localIA,
		neighbouringNodes: scannedNeighbours,
		localInfraNodes:   scannedInfraNodes,
		OutsideWLSetting:  outsideSetting,
		LocalWLSetting:    localSetting,
	}
}
