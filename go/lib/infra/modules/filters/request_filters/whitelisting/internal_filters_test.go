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

	"github.com/scionproto/scion/go/lib/infra/modules/filters"
)

func TestNewInfraNodesFilter(t *testing.T) {
	Convey("Creating a new infra nodes filter", t, func() {
		filter := NewInfraNodesFilter(pathToFile, time.Hour)
		filter1 := NewInfraNodesFilter(pathToFile1, time.Hour)

		Convey("Should fill the infra nodes list of the filter", func() {
			So(filter.InfraNodes, ShouldResemble, scannedInfraNodes)
			So(filter1.InfraNodes, ShouldResemble, scannedInfraNodes1)
		})
	})
}

func TestInfraNodesFilter_FilterPacket(t *testing.T) {
	filter := &InfraNodesFilter{
		InfraNodes: map[string]struct{}{otherHostAddr.String(): {}},
	}

	Convey("An infra nodes filter", t, func() {

		result, err := filter.FilterInternal(externalISDAddr)
		Convey("Should accept an (IP) address that is on the infra node whitelist", func() {
			So(err, ShouldBeNil)
			So(result, ShouldEqual, filters.FilterAccept)
		})

		result, err = filter.FilterInternal(localISDAddr)
		Convey("Should drop an (IP) address that is not on the infra node whitelist", func() {
			So(err, ShouldBeNil)
			So(result, ShouldEqual, filters.FilterDrop)
		})
	})
}
