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
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/snet"
)

var (
	anyHostAddr        = addr.HostFromIPStr("127.0.0.250")
	otherHostAddr      = addr.HostFromIPStr("127.0.0.251")
	IAOfLocalISD, _    = addr.IAFromString("1-ff00:0:100")
	IAOfExternalISD, _ = addr.IAFromString("2-ff00:0:201")

	localISDAddr    = snet.Addr{IA: IAOfLocalISD, Host: &addr.AppAddr{L3: anyHostAddr}}
	externalISDAddr = snet.Addr{IA: IAOfExternalISD, Host: &addr.AppAddr{L3: otherHostAddr}}
)

func TestNewNeighbourFilter(t *testing.T) {
	Convey("Creating a new neighbour filter", t, func() {
		filter := NewNeighbourFilter(pathToFile, time.Hour)
		filter1 := NewNeighbourFilter(pathToFile1, time.Hour)

		Convey("Should fill the neighbour list of the filter with all neighbours", func() {
			So(filter.Neighbours, ShouldResemble, scannedNeighbours)
			So(filter1.Neighbours, ShouldResemble, scannedNeighbours1)
		})
	})
}

func TestNewUpNeighbourFilter(t *testing.T) {
	Convey("Creating a new upstream neighbour filter", t, func() {
		filter := NewUpNeighbourFilter(pathToFile, time.Hour)
		filter1 := NewUpNeighbourFilter(pathToFile1, time.Hour)

		Convey("Should fill the neighbour list of the filter with upstream neighbours", func() {
			So(filter.Neighbours, ShouldResemble, scannedUpNeighbours)
			So(filter1.Neighbours, ShouldResemble, scannedUpNeighbours1)
		})
	})
}

func TestNewDownNeighbourFilter(t *testing.T) {
	Convey("Creating a new downstream neighbour filter", t, func() {
		filter := NewDownNeighbourFilter(pathToFile, time.Hour)
		filter1 := NewDownNeighbourFilter(pathToFile1, time.Hour)

		Convey("Should fill the neighbour list of the filter with downstream neighbours", func() {
			So(filter.Neighbours, ShouldResemble, scannedDownNeighbours)
			So(filter1.Neighbours, ShouldResemble, scannedDownNeighbours1)
		})
	})
}

func TestNewCoreNeighbourFilter(t *testing.T) {
	Convey("Creating a new core neighbour filter", t, func() {
		filter := NewCoreNeighbourFilter(pathToFile, time.Hour)
		filter1 := NewCoreNeighbourFilter(pathToFile1, time.Hour)

		Convey("Should fill the neighbour list of the filter with core neighbours", func() {
			So(filter.Neighbours, ShouldResemble, scannedCoreNeighbours)
			So(filter1.Neighbours, ShouldResemble, scannedCoreNeighbours1)
		})
	})
}

func TestISDFilter_FilterPacket(t *testing.T) {
	isd1, _ := addr.ISDFromString("1")
	filter := &ISDFilter{isd1}

	Convey("An ISD Filter", t, func() {

		result, err := filter.FilterExternal(localISDAddr)
		Convey("Should accept an address from the local ISD", func() {
			So(err, ShouldBeNil)
			So(result, ShouldEqual, filters.FilterAccept)
		})

		result, err = filter.FilterExternal(externalISDAddr)
		Convey("Should drop an address from any other ISD", func() {
			So(err, ShouldBeNil)
			So(result, ShouldEqual, filters.FilterDrop)
		})
	})
}

func TestNeighbourFilter_FilterPacket(t *testing.T) {
	filter := &NeighbourFilter{
		Neighbours: map[addr.IA]struct{}{IAOfExternalISD: {}},
	}

	Convey("A Neighbour Filter", t, func() {

		result, err := filter.FilterExternal(externalISDAddr)
		Convey("Should accept an address that is on the neighbour whitelist", func() {
			So(err, ShouldBeNil)
			So(result, ShouldEqual, filters.FilterAccept)
		})

		result, err = filter.FilterExternal(localISDAddr)
		Convey("Should drop an address that is not on the neighbour whitelist", func() {
			So(err, ShouldBeNil)
			So(result, ShouldEqual, filters.FilterDrop)
		})
	})
}
