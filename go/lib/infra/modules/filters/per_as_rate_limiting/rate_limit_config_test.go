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

func TestRateLimitConfig_Sample(t *testing.T) {
	Convey("Sample correct", t, func() {
		var sample bytes.Buffer
		var cfg RateLimitConfig
		cfg.Sample(&sample, nil, nil)
		meta, err := toml.Decode(sample.String(), &cfg)
		cfg.InitDefaults()
		SoMsg("err", err, ShouldBeNil)
		SoMsg("unparsed", meta.Undecoded(), ShouldBeEmpty)

		SoMsg("Number of clients correct", cfg.NumOfClients, ShouldEqual, 100)
		SoMsg("Interval correct", cfg.Interval.Duration, ShouldEqual, 20*time.Second)
		SoMsg("Max count correct", cfg.MaxCount, ShouldEqual, 5)
	})
}

func TestRateLimitConfig_Validate(t *testing.T) {
	Convey("Validation of a config should fail if", t, func() {

		Convey("Number of clients is 0", func() {
			err := makeConfig(0, time.Second, 10).Validate()
			So(err, ShouldNotBeNil)
		})
		Convey("Number of clients below 0", func() {
			err := makeConfig(-1, time.Second, 10).Validate()
			So(err, ShouldNotBeNil)
		})
		Convey("Max count is 0", func() {
			err := makeConfig(1, time.Second, 0).Validate()
			So(err, ShouldNotBeNil)
		})
		Convey("Max count is below 0", func() {
			err := makeConfig(1, time.Second, -10).Validate()
			So(err, ShouldNotBeNil)
		})
		Convey("Interval is 0", func() {
			err := makeConfig(1, 0*time.Second, 10).Validate()
			So(err, ShouldNotBeNil)
		})
		Convey("Interval is negative", func() {
			err := makeConfig(1, -1*time.Second, 10).Validate()
			So(err, ShouldNotBeNil)
		})
	})
	Convey("Validation of a config should succeed for a valid config", t, func() {

		err := makeConfig(10, time.Second, 10).Validate()
		So(err, ShouldBeNil)
	})
}

func TestRateLimitConfig_InitDefaults(t *testing.T) {
	Convey("Initialising defaults should", t, func() {

		cfg := &RateLimitConfig{
			NumOfClients: 10,
		}
		cfg.InitDefaults()

		Convey("Set the interval to the default value", func() {
			So(cfg.Interval.Duration, ShouldEqual, defaultInterval)
		})
		Convey("Set the max count to the default value", func() {
			So(cfg.MaxCount, ShouldEqual, int(defaultMaxCount))
		})
	})
}

func makeConfig(clients int, interval time.Duration, max int) *RateLimitConfig {
	return &RateLimitConfig{
		NumOfClients: clients,
		Interval:     duration{interval},
		MaxCount:     max,
	}
}
