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
	"testing"

	"github.com/BurntSushi/toml"
	. "github.com/smartystreets/goconvey/convey"
)

func TestRequestConfig_Sample(t *testing.T) {
	Convey("Sample correct", t, func() {
		var sample bytes.Buffer
		var cfg RequestConfig
		cfg.Sample(&sample, nil, nil)
		meta, err := toml.Decode(sample.String(), &cfg)
		SoMsg("Decoding err", err, ShouldBeNil)
		err = cfg.Validate()
		SoMsg("Validation err", err, ShouldBeNil)
		SoMsg("unparsed", meta.Undecoded(), ShouldBeEmpty)

		SoMsg("Internal WL setting correct", cfg.InternalWL, ShouldEqual, InfraWL)
		SoMsg("External WL setting correct", cfg.ExternalWL, ShouldEqual, ISDWL)
		SoMsg("Internal rate limit setting correct", cfg.InternalRateLimit, ShouldEqual, IntervalRL)
		SoMsg("External rate limit setting correct", cfg.ExternalRateLimit, ShouldEqual, HistoryRL)
		SoMsg("Checking internal for empty path correct", cfg.CheckInternalForEmptyPath, ShouldBeTrue)
		SoMsg("Limiting external to neighbours correct", cfg.LimitExternalToNeighbours, ShouldBeFalse)
		SoMsg("Segment filter setting correct", cfg.SegmentFiltering, ShouldEqual, Core)
	})
}

func TestRequestConfig_Validate(t *testing.T) {
	Convey("Validation of a request config should fail if", t, func() {

		Convey("Invalid value for internal whitelist setting", func() {
			err := makeConfig("Infr", ISDWL, IntervalRL, HistoryRL).Validate()
			So(err, ShouldNotBeNil)
		})
		Convey("Invalid value for external whitelist setting", func() {
			err := makeConfig(InfraWL, "ISDD", IntervalRL, HistoryRL).Validate()
			So(err, ShouldNotBeNil)
		})
		Convey("Invalid value for internal rate limit setting", func() {
			err := makeConfig(InfraWL, ISDWL, "anything", HistoryRL).Validate()
			So(err, ShouldNotBeNil)
		})
		Convey("Invalid value for external rate limit setting ", func() {
			err := makeConfig(InfraWL, ISDWL, IntervalRL, "history").Validate()
			So(err, ShouldNotBeNil)
		})
		Convey("Invalid value for segment filter setting ", func() {
			err := makeConfig2(false, "invalid").Validate()
			So(err, ShouldNotBeNil)
		})
		Convey("Neighbour path length filtering and segment filter set ", func() {
			err := makeConfig2(true, Core).Validate()
			So(err, ShouldNotBeNil)
		})
	})

	Convey("Validation of a request config should not fail", t, func() {

		Convey("If nothing is set", func() {
			err := makeConfig(Nothing, Nothing, Nothing, Nothing).Validate()
			So(err, ShouldBeNil)
		})
	})
}

func makeConfig(internalWL, externalWL, internalRL, externalRL string) *RequestConfig {
	return &RequestConfig{
		InternalWL:        internalWL,
		ExternalWL:        externalWL,
		InternalRateLimit: internalRL,
		ExternalRateLimit: externalRL,
	}
}

func makeConfig2(limitNeighbours bool, segFilterSetting string) *RequestConfig {
	return &RequestConfig{
		LimitExternalToNeighbours: limitNeighbours,
		SegmentFiltering:          segFilterSetting,
	}
}
