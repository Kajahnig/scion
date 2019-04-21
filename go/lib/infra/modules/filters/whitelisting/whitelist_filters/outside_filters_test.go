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
	"testing"

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
	localISDAddr       = snet.SCIONAddress{IA: IAOfLocalISD, Host: anyHostAddr}
	externalISDAddr    = snet.SCIONAddress{IA: IAOfExternalISD, Host: otherHostAddr}
)

func TestISDFilter_FilterPacket(t *testing.T) {
	isd1, _ := addr.ISDFromString("1")
	filter := &ISDFilter{isd1}

	Convey("An ISD Filter", t, func() {

		result, err := filter.FilterPacket(&localISDAddr)
		Convey("Should accept an address from the local ISD", func() {
			So(err, ShouldBeNil)
			So(result, ShouldEqual, filters.FilterAccept)
		})

		result, err = filter.FilterPacket(&externalISDAddr)
		Convey("Should drop an address from any other ISD", func() {
			So(err, ShouldBeNil)
			So(result, ShouldEqual, filters.FilterDrop)
		})
	})
}

func TestNeighbourFilter_FilterPacket(t *testing.T) {
	filter := &NeighbourFilter{
		Neighbours: map[addr.IA]bool{IAOfExternalISD: true},
	}

	Convey("A Neighbour Filter", t, func() {

		result, err := filter.FilterPacket(&externalISDAddr)
		Convey("Should accept an address that is on the neighbour whitelist", func() {
			So(err, ShouldBeNil)
			So(result, ShouldEqual, filters.FilterAccept)
		})

		result, err = filter.FilterPacket(&localISDAddr)
		Convey("Should drop an address that is not on the neighbour whitelist", func() {
			So(err, ShouldBeNil)
			So(result, ShouldEqual, filters.FilterDrop)
		})
	})
}
