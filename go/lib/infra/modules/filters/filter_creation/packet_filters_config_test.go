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

package filter_creation

import (
	"bytes"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/drkey_filter"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/path_length"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/per_as_rate_limiting"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/whitelisting"
)

func TestPacketFilterConfig(t *testing.T) {
	Convey("Sample correct", t, func() {
		var sample bytes.Buffer
		var cfg PacketFilterConfig
		cfg.Sample(&sample, nil, nil)
		meta, err := toml.Decode(sample.String(), &cfg)
		SoMsg("err", err, ShouldBeNil)
		validationErr := cfg.Validate()
		SoMsg("validation err", validationErr, ShouldBeNil)
		SoMsg("unparsed", meta.Undecoded(), ShouldBeEmpty)

		SoMsg("MinPathlength correct", cfg.Pathlength.MinPathLength, ShouldEqual, 1)
		SoMsg("MaxPathLength correct", cfg.Pathlength.MaxPathLength, ShouldEqual, 2)
		SoMsg("DRkey present", cfg.Drkey, ShouldNotBeNil)
		SoMsg("Number of local clients correct", cfg.PerASRateLimit.LocalClients, ShouldEqual, 100)
		SoMsg("Number of outside ASes correct", cfg.PerASRateLimit.OutsideASes, ShouldEqual, 5)
		SoMsg("Local interval correct", cfg.PerASRateLimit.LocalInterval.Duration, ShouldEqual, 20*time.Second)
		SoMsg("Outside interval correct", cfg.PerASRateLimit.OutsideInterval.Duration, ShouldEqual, 50*time.Second)
		SoMsg("Local Max count correct", cfg.PerASRateLimit.LocalMaxCount, ShouldEqual, 1)
		SoMsg("Outside Max count correct", cfg.PerASRateLimit.OutsideMaxCount, ShouldEqual, 3)
		SoMsg("Path to topology file correct", cfg.Whitelist.PathToTopoFile, ShouldEqual, "../whitelisting/topology.json")
		SoMsg("Rescanning interval correct", cfg.Whitelist.RescanInterval.Duration, ShouldEqual, 40*time.Minute)
		SoMsg("Outside WL setting correct", cfg.Whitelist.OutsideWLSetting.OutsideWLSetting, ShouldEqual, whitelisting.WLISD)
		SoMsg("Local WL setting correct", cfg.Whitelist.LocalWLSetting.LocalWLSetting, ShouldEqual, whitelisting.WLLocalInfraNodes)

	})

	Convey("Sample with only path length filter correct", t, func() {
		var sample bytes.Buffer
		var cfg PacketFilterConfig
		config.WriteSample(&sample, nil, nil, &(path_length.PathLengthConfig{}))
		meta, err := toml.Decode(sample.String(), &cfg)
		SoMsg("err", err, ShouldBeNil)
		validationErr := cfg.Validate()
		SoMsg("validation err", validationErr, ShouldBeNil)
		SoMsg("unparsed", meta.Undecoded(), ShouldBeEmpty)

		SoMsg("Path Length Filter present", cfg.Pathlength, ShouldNotBeNil)
		SoMsg("No DRKey filter config", cfg.Drkey, ShouldBeNil)
		SoMsg("No per AS rate limit filter config", cfg.PerASRateLimit, ShouldBeNil)
		SoMsg("No whitelist filter config", cfg.Whitelist, ShouldBeNil)
	})

	Convey("Sample with only drkey filter correct", t, func() {
		var sample bytes.Buffer
		var cfg PacketFilterConfig
		config.WriteSample(&sample, nil, nil, &(drkey_filter.DRKeyConfig{}))
		meta, err := toml.Decode(sample.String(), &cfg)
		SoMsg("err", err, ShouldBeNil)
		validationErr := cfg.Validate()
		SoMsg("validation err", validationErr, ShouldBeNil)
		SoMsg("unparsed", meta.Undecoded(), ShouldBeEmpty)

		SoMsg("No Path Length Filter config", cfg.Pathlength, ShouldBeNil)
		SoMsg("DRkey filter config present", cfg.Drkey, ShouldNotBeNil)
		SoMsg("No per as rate limit Filter config", cfg.PerASRateLimit, ShouldBeNil)
		SoMsg("No whitelist filter config", cfg.Whitelist, ShouldBeNil)
	})

	Convey("Sample with only per AS rate limiting filter correct", t, func() {
		var sample bytes.Buffer
		var cfg PacketFilterConfig
		config.WriteSample(&sample, nil, nil, &(per_as_rate_limiting.PerASRateLimitConfig{}))
		meta, err := toml.Decode(sample.String(), &cfg)
		SoMsg("err", err, ShouldBeNil)
		validationErr := cfg.Validate()
		SoMsg("validation err", validationErr, ShouldBeNil)
		SoMsg("unparsed", meta.Undecoded(), ShouldBeEmpty)

		SoMsg("No Path Length Filter config", cfg.Pathlength, ShouldBeNil)
		SoMsg("No DRkey filter config", cfg.Drkey, ShouldBeNil)
		SoMsg("Per AS filter config present", cfg.PerASRateLimit, ShouldNotBeNil)
		SoMsg("No whitelist filter config", cfg.Whitelist, ShouldBeNil)
	})

	Convey("Sample with only per AS rate limiting filter correct", t, func() {
		var sample bytes.Buffer
		var cfg PacketFilterConfig
		config.WriteSample(&sample, nil, nil, &(whitelisting.WhitelistConfig{}))
		meta, err := toml.Decode(sample.String(), &cfg)
		SoMsg("err", err, ShouldBeNil)
		validationErr := cfg.Validate()
		SoMsg("validation err", validationErr, ShouldBeNil)
		SoMsg("unparsed", meta.Undecoded(), ShouldBeEmpty)

		SoMsg("No Path Length Filter config", cfg.Pathlength, ShouldBeNil)
		SoMsg("No DRkey filter config", cfg.Drkey, ShouldBeNil)
		SoMsg("No Per AS filter config", cfg.PerASRateLimit, ShouldBeNil)
		SoMsg("Whitelist filter config present", cfg.Whitelist, ShouldNotBeNil)
	})
}
