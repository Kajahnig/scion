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

func TestPerASRateLimitConfig_Sample(t *testing.T) {
	Convey("Sample correct", t, func() {
		var sample bytes.Buffer
		var cfg PerASRateLimitConfig
		cfg.Sample(&sample, nil, nil)
		meta, err := toml.Decode(sample.String(), &cfg)
		cfg.InitDefaults()
		SoMsg("err", err, ShouldBeNil)
		SoMsg("unparsed", meta.Undecoded(), ShouldBeEmpty)

		SoMsg("Number of local clients correct", cfg.LocalClients, ShouldEqual, 100)
		SoMsg("Number of outside ASes correct", cfg.OutsideASes, ShouldEqual, 5)
		SoMsg("Local interval correct", cfg.LocalInterval.Duration, ShouldEqual, 20*time.Second)
		SoMsg("Outside interval correct", cfg.OutsideInterval.Duration, ShouldEqual, 50*time.Second)
		SoMsg("Local Max count correct", cfg.LocalMaxCount, ShouldEqual, 1)
		SoMsg("Outside Max count correct", cfg.OutsideMaxCount, ShouldEqual, 3)
	})
}

func TestPerASRateLimitConfig_Validate(t *testing.T) {
	Convey("Validation of a config should fail if", t, func() {

		Convey("Number of local clients below 0", func() {
			err := makeConfig(-1, 4, time.Second, time.Second, 10, 20).Validate()
			So(err, ShouldNotBeNil)
		})
		Convey("Number of outside ASes below 0", func() {
			err := makeConfig(1, -4, time.Second, time.Second, 10, 20).Validate()
			So(err, ShouldNotBeNil)
		})
		Convey("Local Max count is 0", func() {
			err := makeConfig(1, 4, time.Second, time.Second, 0, 20).Validate()
			So(err, ShouldNotBeNil)
		})
		Convey("Outside max count is below 0", func() {
			err := makeConfig(1, 4, time.Second, time.Second, 10, -20).Validate()
			So(err, ShouldNotBeNil)
		})
		Convey("Local Interval is 0", func() {
			err := makeConfig(1, 4, 0*time.Second, time.Second, 10, 20).Validate()
			So(err, ShouldNotBeNil)
		})
		Convey("Outside Interval is below 0", func() {
			err := makeConfig(1, 4, time.Second, -1*time.Second, 10, 20).Validate()
			So(err, ShouldNotBeNil)
		})
	})
}

func TestPerASRateLimitConfig_InitDefaults(t *testing.T) {
	Convey("Initialising defaults should", t, func() {

		cfg := &PerASRateLimitConfig{
			LocalClients: 10,
			OutsideASes:  20,
		}
		cfg.InitDefaults()

		Convey("Set the intervals to the default value", func() {
			So(cfg.LocalInterval.Duration, ShouldEqual, defaultInterval)
			So(cfg.OutsideInterval.Duration, ShouldEqual, defaultInterval)
		})
		Convey("Set the max counts to the default value", func() {
			So(cfg.LocalMaxCount, ShouldEqual, int(defaultMaxCount))
			So(cfg.OutsideMaxCount, ShouldEqual, int(defaultMaxCount))
		})
	})
}

func makeConfig(local, outside int, linterval, ointerval time.Duration, lmax, omax int) *PerASRateLimitConfig {
	return &PerASRateLimitConfig{
		LocalClients:    local,
		OutsideASes:     outside,
		LocalInterval:   duration{linterval},
		OutsideInterval: duration{ointerval},
		LocalMaxCount:   lmax,
		OutsideMaxCount: omax,
	}
}
