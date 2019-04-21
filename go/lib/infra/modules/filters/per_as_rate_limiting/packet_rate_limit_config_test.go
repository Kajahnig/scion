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

package per_as_rate_limiting

import (
	"bytes"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	. "github.com/smartystreets/goconvey/convey"
)

// Test validation failing if both are nil

func TestPacketRateLimitConfig_Sample(t *testing.T) {
	Convey("Sample correct", t, func() {
		var sample bytes.Buffer
		var cfg PacketRateLimitConfig
		cfg.Sample(&sample, nil, nil)
		meta, err := toml.Decode(sample.String(), &cfg)
		cfg.InitDefaults()
		SoMsg("err", err, ShouldBeNil)
		SoMsg("unparsed", meta.Undecoded(), ShouldBeEmpty)

		SoMsg("Number of clients correct", cfg.LocalConfig.NumOfClients, ShouldEqual, 100)
		SoMsg("Number of clients correct", cfg.OutsideConfig.NumOfClients, ShouldEqual, 100)
		SoMsg("Interval correct", cfg.LocalConfig.Interval.Duration, ShouldEqual, 20*time.Second)
		SoMsg("Interval correct", cfg.OutsideConfig.Interval.Duration, ShouldEqual, 20*time.Second)
		SoMsg("Max count correct", cfg.LocalConfig.MaxCount, ShouldEqual, 5)
		SoMsg("Max count correct", cfg.OutsideConfig.MaxCount, ShouldEqual, 5)
	})
}

func TestPacketRateLimitConfig_Validate(t *testing.T) {
	Convey("Validation of a config should fail if", t, func() {

		Convey("The validation of the local config fails (Number of clients is 0)", func() {
			err := PacketRateLimitConfig{
				LocalConfig: &RateLimitConfig{
					0,
					duration{time.Second},
					10},
				OutsideConfig: nil,
			}.Validate()
			So(err, ShouldNotBeNil)
		})
		Convey("The validation of the outside config fails (Max count is 0)", func() {
			err := PacketRateLimitConfig{
				OutsideConfig: &RateLimitConfig{
					10,
					duration{time.Second},
					0},
				LocalConfig: nil,
			}.Validate()
			So(err, ShouldNotBeNil)
		})
		Convey("Both configs are nil", func() {
			err := PacketRateLimitConfig{nil, nil}.Validate()
			So(err, ShouldNotBeNil)
		})
	})
	Convey("Validation of a config should succeed for a correct config", t, func() {

		Convey("The validation of the local config fails (Number of clients is 0)", func() {
			err := PacketRateLimitConfig{
				LocalConfig: &RateLimitConfig{
					5,
					duration{time.Second},
					10},
				OutsideConfig: &RateLimitConfig{
					50,
					duration{3 * time.Second},
					100},
			}.Validate()
			So(err, ShouldBeNil)
		})
	})
}
