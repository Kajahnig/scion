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
	"github.com/scionproto/scion/bazel-scion/external/go_sdk/src/fmt"
	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"reflect"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/whitelisting/whitelist_filters"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	pathToFile  = "./topology.json"
	pathToFile1 = "./topology1.json"
)

// This test uses the topology.json and topology1.json files in the same folder.
//They are copies of the topology.json from AS211 and AS120 of the default topology.
var (
	localIA, _ = addr.IAFromString("2-ff00:0:211")
	AS210, _   = addr.IAFromString("2-ff00:0:210")
	AS212, _   = addr.IAFromString("2-ff00:0:212")
	AS220, _   = addr.IAFromString("2-ff00:0:220")
	AS111, _   = addr.IAFromString("1-ff00:0:111")
	AS130, _   = addr.IAFromString("1-ff00:0:130")
	AS131, _   = addr.IAFromString("1-ff00:0:131")

	anyHostAddr   = addr.HostFromIPStr("127.0.0.250")
	infraHostAddr = addr.HostFromIPStr("127.0.0.209")

	localNonInfraPacket = packetFrom(snet.SCIONAddress{IA: localIA, Host: anyHostAddr})
	localInfraPacket    = packetFrom(snet.SCIONAddress{IA: localIA, Host: infraHostAddr})
	AS210p              = packetFrom(snet.SCIONAddress{IA: AS210, Host: anyHostAddr})
	AS212p              = packetFrom(snet.SCIONAddress{IA: AS212, Host: anyHostAddr})
	AS220p              = packetFrom(snet.SCIONAddress{IA: AS220, Host: anyHostAddr})
	AS111p              = packetFrom(snet.SCIONAddress{IA: AS111, Host: anyHostAddr})
	AS130p              = packetFrom(snet.SCIONAddress{IA: AS130, Host: anyHostAddr})
	AS131p              = packetFrom(snet.SCIONAddress{IA: AS131, Host: anyHostAddr})
)

func TestNewWhitelistFilterFromConfig(t *testing.T) {

	Convey("Creating a new whitelist filter from a config", t, func() {

		filter, _ := NewWhitelistFilterFromConfig(localConfig(AcceptLocal))
		Convey("Should set the local IA to the correct value", func() {
			So(filter.localIA, ShouldResemble, localIA)
		})

		Convey("Should set the local filters correctly", func() {
			filter, _ := NewWhitelistFilterFromConfig(localConfig(DropLocal))
			So(reflect.TypeOf(*filter.LocalFilter), ShouldEqual, reflect.TypeOf(&whitelist_filters.DroppingFilter{}))

			filter, _ = NewWhitelistFilterFromConfig(localConfig(AcceptLocal))
			So(reflect.TypeOf(*filter.LocalFilter), ShouldEqual, reflect.TypeOf(&whitelist_filters.AcceptingFilter{}))

			filter, _ = NewWhitelistFilterFromConfig(localConfig(AcceptInfraNodes))
			So(reflect.TypeOf(*filter.LocalFilter), ShouldEqual, reflect.TypeOf(&whitelist_filters.InfraNodesFilter{}))
		})

		Convey("Should set the outside filters correctly", func() {
			filter, _ := NewWhitelistFilterFromConfig(outsideConfig(Drop))
			So(reflect.TypeOf(*filter.OutsideFilter), ShouldEqual, reflect.TypeOf(&whitelist_filters.DroppingFilter{}))

			filter, _ = NewWhitelistFilterFromConfig(outsideConfig(Accept))
			So(reflect.TypeOf(*filter.OutsideFilter), ShouldEqual, reflect.TypeOf(&whitelist_filters.AcceptingFilter{}))

			filter, _ = NewWhitelistFilterFromConfig(outsideConfig(AcceptISD))
			So(reflect.TypeOf(*filter.OutsideFilter), ShouldEqual, reflect.TypeOf(&whitelist_filters.ISDFilter{}))

			filter, _ = NewWhitelistFilterFromConfig(outsideConfig(AcceptNeighbours))
			So(reflect.TypeOf(*filter.OutsideFilter), ShouldEqual, reflect.TypeOf(&whitelist_filters.NeighbourFilter{}))

			filter, _ = NewWhitelistFilterFromConfig(outsideConfig(AcceptUpstreamNeighbours))
			So(reflect.TypeOf(*filter.OutsideFilter), ShouldEqual, reflect.TypeOf(&whitelist_filters.NeighbourFilter{}))

			filter, _ = NewWhitelistFilterFromConfig(outsideConfig(AcceptDownstreamNeighbours))
			So(reflect.TypeOf(*filter.OutsideFilter), ShouldEqual, reflect.TypeOf(&whitelist_filters.NeighbourFilter{}))

			filter, _ = NewWhitelistFilterFromConfig(outsideConfig(AcceptCoreNeighbours))
			So(reflect.TypeOf(*filter.OutsideFilter), ShouldEqual, reflect.TypeOf(&whitelist_filters.NeighbourFilter{}))
		})

	})
}

func TestWhitelistFilter_FilterPacket_LocalTraffic(t *testing.T) {

	Convey("Filtering with local setting", t, func() {
		Convey("Accept", func() {
			filter, _ := NewWhitelistFilterFromConfig(localConfig(AcceptLocal))
			checkAnswersForLocalPackets(filter, filters.FilterAccept, filters.FilterAccept)
		})

		Convey("Drop", func() {
			filter, _ := NewWhitelistFilterFromConfig(localConfig(DropLocal))
			checkAnswersForLocalPackets(filter, filters.FilterDrop, filters.FilterDrop)
		})

		Convey("Infra", func() {
			filter, _ := NewWhitelistFilterFromConfig(localConfig(AcceptInfraNodes))
			checkAnswersForLocalPackets(filter, filters.FilterDrop, filters.FilterAccept)
		})
	})
}

func checkAnswersForLocalPackets(filter *WhitelistFilter, er1, er2 filters.FilterResult) {
	r1, _ := filter.FilterPacket(localNonInfraPacket)
	r2, _ := filter.FilterPacket(localInfraPacket)

	SoMsg(fmt.Sprintf("Answer to a local non-infra packet is %v", er1.ToString()), r1, ShouldEqual, er1)
	SoMsg(fmt.Sprintf("Answer to a local infra packet is %v", er2.ToString()), r2, ShouldEqual, er2)
}

func TestWhitelistFilter_FilterPacket_OutsideTraffic_AS211(t *testing.T) {
	Convey("Filtering with outside settings", t, func() {
		Convey("Accept", func() {
			filter, _ := NewWhitelistFilterFromConfig(outsideConfig(Accept))
			checkAnswersForAS211(filter, filters.FilterAccept, filters.FilterAccept, filters.FilterAccept, filters.FilterAccept)
		})
		Convey("Drop", func() {
			filter, _ := NewWhitelistFilterFromConfig(outsideConfig(Drop))
			checkAnswersForAS211(filter, filters.FilterDrop, filters.FilterDrop, filters.FilterDrop, filters.FilterDrop)
		})
		Convey("ISD", func() {
			filter, _ := NewWhitelistFilterFromConfig(outsideConfig(AcceptISD))
			checkAnswersForAS211(filter, filters.FilterAccept, filters.FilterAccept, filters.FilterAccept, filters.FilterDrop)
		})
		Convey("Neighbours", func() {
			filter, _ := NewWhitelistFilterFromConfig(outsideConfig(AcceptNeighbours))
			checkAnswersForAS211(filter, filters.FilterAccept, filters.FilterAccept, filters.FilterDrop, filters.FilterAccept)
		})
		Convey("Up", func() {
			filter, _ := NewWhitelistFilterFromConfig(outsideConfig(AcceptUpstreamNeighbours))
			checkAnswersForAS211(filter, filters.FilterAccept, filters.FilterDrop, filters.FilterDrop, filters.FilterDrop)
		})
		Convey("Down", func() {
			filter, _ := NewWhitelistFilterFromConfig(outsideConfig(AcceptDownstreamNeighbours))
			checkAnswersForAS211(filter, filters.FilterDrop, filters.FilterAccept, filters.FilterDrop, filters.FilterDrop)
		})
	})
}

func checkAnswersForAS211(filter *WhitelistFilter, er1, er2, er3, er4 filters.FilterResult) {
	r1, _ := filter.FilterPacket(AS210p)
	r2, _ := filter.FilterPacket(AS212p)
	r3, _ := filter.FilterPacket(AS220p)
	r4, _ := filter.FilterPacket(AS111p)

	SoMsg(fmt.Sprintf("Answer to AS210 is %v", er1.ToString()), r1, ShouldEqual, er1)
	SoMsg(fmt.Sprintf("Answer to AS212 is %v", er2.ToString()), r2, ShouldEqual, er2)
	SoMsg(fmt.Sprintf("Answer to AS220 is %v", er3.ToString()), r3, ShouldEqual, er3)
	SoMsg(fmt.Sprintf("Answer to AS111 is %v", er4.ToString()), r4, ShouldEqual, er4)
}

func TestWhitelistFilter_FilterPacket_OutsideTraffic_AS120(t *testing.T) {
	Convey("Filtering with outside settings", t, func() {
		Convey("ISD", func() {
			filter, _ := NewWhitelistFilterFromConfig(outsideConfig1(AcceptISD))
			checkAnswersForAS120(filter, filters.FilterAccept, filters.FilterAccept, filters.FilterAccept,
				filters.FilterDrop, filters.FilterDrop)
		})
		Convey("Neighbours", func() {
			filter, _ := NewWhitelistFilterFromConfig(outsideConfig1(AcceptNeighbours))
			checkAnswersForAS120(filter, filters.FilterAccept, filters.FilterAccept, filters.FilterDrop,
				filters.FilterDrop, filters.FilterAccept)
		})
		Convey("Up", func() {
			filter, _ := NewWhitelistFilterFromConfig(outsideConfig1(AcceptUpstreamNeighbours))
			checkAnswersForAS120(filter, filters.FilterDrop, filters.FilterDrop, filters.FilterDrop,
				filters.FilterDrop, filters.FilterDrop)
		})
		Convey("Down", func() {
			filter, _ := NewWhitelistFilterFromConfig(outsideConfig1(AcceptDownstreamNeighbours))
			checkAnswersForAS120(filter, filters.FilterAccept, filters.FilterDrop, filters.FilterDrop,
				filters.FilterDrop, filters.FilterDrop)
		})
		Convey("Core", func() {
			filter, _ := NewWhitelistFilterFromConfig(outsideConfig1(AcceptCoreNeighbours))
			checkAnswersForAS120(filter, filters.FilterDrop, filters.FilterAccept, filters.FilterDrop,
				filters.FilterDrop, filters.FilterAccept)
		})
	})
}

func checkAnswersForAS120(filter *WhitelistFilter, er1, er2, er3, er4, er5 filters.FilterResult) {
	r1, _ := filter.FilterPacket(AS111p)
	r2, _ := filter.FilterPacket(AS130p)
	r3, _ := filter.FilterPacket(AS131p)
	r4, _ := filter.FilterPacket(AS210p)
	r5, _ := filter.FilterPacket(AS220p)

	SoMsg(fmt.Sprintf("Answer to AS111 is %v", er1.ToString()), r1, ShouldEqual, er1)
	SoMsg(fmt.Sprintf("Answer to AS130 is %v", er2.ToString()), r2, ShouldEqual, er2)
	SoMsg(fmt.Sprintf("Answer to AS131 is %v", er3.ToString()), r3, ShouldEqual, er3)
	SoMsg(fmt.Sprintf("Answer to AS210 is %v", er4.ToString()), r4, ShouldEqual, er4)
	SoMsg(fmt.Sprintf("Answer to AS220 is %v", er5.ToString()), r5, ShouldEqual, er5)
}

func localConfig(setting LocalWLSetting) *WhitelistConfig {
	cfg := &WhitelistConfig{
		PathToTopoFile: pathToFile,
		LocalSetting:   localSetting{setting},
		OutsideSetting: outsideSetting{Accept},
	}
	cfg.InitDefaults()
	return cfg
}

func outsideConfig(setting OutsideWLSetting) *WhitelistConfig {
	return outsideConfigWithPath(setting, pathToFile)
}

func outsideConfig1(setting OutsideWLSetting) *WhitelistConfig {
	return outsideConfigWithPath(setting, pathToFile1)
}

func outsideConfigWithPath(setting OutsideWLSetting, path string) *WhitelistConfig {
	cfg := &WhitelistConfig{
		PathToTopoFile: path,
		OutsideSetting: outsideSetting{setting},
		LocalSetting:   localSetting{AcceptLocal},
	}
	cfg.InitDefaults()
	return cfg
}

func packetFrom(addr snet.SCIONAddress) *snet.SCIONPacket {
	return &snet.SCIONPacket{
		Bytes: nil,
		SCIONPacketInfo: snet.SCIONPacketInfo{
			Source: addr,
		},
	}
}
