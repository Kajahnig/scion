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

	"github.com/BurntSushi/toml"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/packet_filters/drkey_filter"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/packet_filters/path_length"
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

		SoMsg("AllowEmptyPaths correct", cfg.Pathlength.AllowEmptyPaths, ShouldBeTrue)
		SoMsg("DisallowPaths correct", cfg.Pathlength.DisallowPaths, ShouldBeFalse)
		SoMsg("MinPathlength correct", cfg.Pathlength.MinPathLength, ShouldEqual, 1)
		SoMsg("MaxPathLength correct", cfg.Pathlength.MaxPathLength, ShouldEqual, 2)
		SoMsg("DRkey internal correct", cfg.Drkey.InternalFiltering, ShouldBeTrue)
		SoMsg("DRkey external correct", cfg.Drkey.ExternalFiltering, ShouldBeFalse)
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
	})
}
