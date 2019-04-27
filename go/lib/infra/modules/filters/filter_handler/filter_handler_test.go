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

package filter_handler

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/BurntSushi/toml"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/per_as_rate_limiting"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/request_filters/whitelisting"
)

func TestNew(t *testing.T) {
	//return the original handler if not config for the request is present
	//fill the corresponding arrays with the correct handlers in the appropriate sequence
	Convey("Calling New should", t, func() {
		initTest()

		Convey("Return the original handler on a request that is not in the config", func() {
			handler := New(infra.SegReg, nil)
			So(handler, ShouldBeNil)
		})

		Convey("Return the correct filter handler on a request that is in the config", func() {
			handler := New(infra.TRCRequest, nil)
			filterhandler := handler.(*FilterHandler)
			So(filterhandler.originalHandler, ShouldBeNil)
			So(reflect.TypeOf(filterhandler.internalFilters[0]), ShouldEqual,
				reflect.TypeOf(&whitelisting.InfraNodesFilter{}))
			So(reflect.TypeOf(filterhandler.internalFilters[1]), ShouldEqual,
				reflect.TypeOf(&per_as_rate_limiting.RateLimitFilter{}))
			So(reflect.TypeOf(filterhandler.externalFilters[0]), ShouldEqual,
				reflect.TypeOf(&whitelisting.ISDFilter{}))
			So(reflect.TypeOf(filterhandler.externalFilters[1]), ShouldEqual,
				reflect.TypeOf(&per_as_rate_limiting.RateLimitFilter{}))
		})
	})

}

func Test_newInternalWLFilter(t *testing.T) {
	Convey("Calling newInternalWLFilter should", t, func() {
		initTest()
		filterD := newInternalWLFilter("Drop")
		filterI := newInternalWLFilter("Infra")

		Convey("Return the correct whitelisting filters", func() {
			So(reflect.TypeOf(filterD), ShouldEqual, reflect.TypeOf(&whitelisting.DroppingFilter{}))
			So(reflect.TypeOf(filterI), ShouldEqual, reflect.TypeOf(&whitelisting.InfraNodesFilter{}))
		})

		filterD2 := newInternalWLFilter("Drop")
		filterI2 := newInternalWLFilter("Infra")

		Convey("Return the same filters on a second call", func() {
			So(filterD, ShouldEqual, filterD2)
			So(filterI, ShouldEqual, filterI2)
		})
	})
}

func Test_newExternalWLFilter(t *testing.T) {
	Convey("Calling newExternalWLFilter should", t, func() {
		initTest()
		filterDrop := newExternalWLFilter("Drop")
		filterI := newExternalWLFilter("ISD")
		filterN := newExternalWLFilter("Neighbours")
		filterU := newExternalWLFilter("UpNeighbours")
		filterD := newExternalWLFilter("DownNeighbours")
		filterC := newExternalWLFilter("CoreNeighbours")

		Convey("Return the correct whitelisting filters", func() {
			So(reflect.TypeOf(filterDrop), ShouldEqual, reflect.TypeOf(&whitelisting.DroppingFilter{}))
			So(reflect.TypeOf(filterI), ShouldEqual, reflect.TypeOf(&whitelisting.ISDFilter{}))
			So(reflect.TypeOf(filterN), ShouldEqual, reflect.TypeOf(&whitelisting.NeighbourFilter{}))
			So(reflect.TypeOf(filterU), ShouldEqual, reflect.TypeOf(&whitelisting.NeighbourFilter{}))
			So(reflect.TypeOf(filterD), ShouldEqual, reflect.TypeOf(&whitelisting.NeighbourFilter{}))
			So(reflect.TypeOf(filterC), ShouldEqual, reflect.TypeOf(&whitelisting.NeighbourFilter{}))
		})

		Convey("That are all different from each other", func() {
			So(filterN, ShouldNotEqual, filterU)
			So(filterN, ShouldNotEqual, filterD)
			So(filterN, ShouldNotEqual, filterC)
			So(filterU, ShouldNotEqual, filterD)
			So(filterU, ShouldNotEqual, filterC)
			So(filterC, ShouldNotEqual, filterD)
		})

		filterDrop2 := newExternalWLFilter("Drop")
		filterI2 := newExternalWLFilter("ISD")
		filterN2 := newExternalWLFilter("Neighbours")
		filterU2 := newExternalWLFilter("UpNeighbours")
		filterD2 := newExternalWLFilter("DownNeighbours")
		filterC2 := newExternalWLFilter("CoreNeighbours")

		Convey("Return the same filters on a second call", func() {
			So(filterDrop, ShouldEqual, filterDrop2)
			So(filterI, ShouldEqual, filterI2)
			So(filterN, ShouldEqual, filterN2)
			So(filterU, ShouldEqual, filterU2)
			So(filterD, ShouldEqual, filterD2)
			So(filterC, ShouldEqual, filterC2)
		})
	})
}

func Test_newInternalRLFilter(t *testing.T) {
	Convey("Calling newInternalRLFilter should", t, func() {
		initTest()
		filter := newInternalRLFilter("Interval")

		Convey("Return an interval request limiting filter", func() {
			So(reflect.TypeOf(filter), ShouldEqual, reflect.TypeOf(&per_as_rate_limiting.RateLimitFilter{}))
		})
		filter2 := newInternalRLFilter("Interval")
		Convey("Return the same interval request limiting filter on a second call", func() {
			So(filter, ShouldEqual, filter2)
		})
		filter3 := newExternalRLFilter("Interval")
		Convey("Return a different interval request limiting filter on a call to external func", func() {
			So(filter2, ShouldNotEqual, filter3)
		})
	})
}

func Test_newExternalRLFilter(t *testing.T) {
	Convey("Calling newExternalRLFilter should", t, func() {
		initTest()
		filter := newExternalRLFilter("Interval")

		Convey("Return an interval request limiting filter", func() {
			So(reflect.TypeOf(filter), ShouldEqual, reflect.TypeOf(&per_as_rate_limiting.RateLimitFilter{}))
		})
		filter2 := newExternalRLFilter("Interval")
		Convey("Return the same interval request limiting filter on a second call", func() {
			So(filter, ShouldEqual, filter2)
		})
	})
}

func initTest() {
	var sample bytes.Buffer
	var cfg FilterHandlerConfig
	var IA, _ = addr.IAFromString("1-ff00:0:100")
	cfg.Sample(&sample, nil, nil)
	_, err := toml.Decode(sample.String(), &cfg)
	SoMsg("No decoding error", err, ShouldBeNil)
	err = Init(IA, &cfg, "../whitelisting/topology.json")
	SoMsg("No initialisation error", err, ShouldBeNil)
}
