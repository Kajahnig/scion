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

package path_length

import (
	"bytes"
	"testing"

	"github.com/BurntSushi/toml"
	. "github.com/smartystreets/goconvey/convey"
)

func TestPathLengthConfig_Sample(t *testing.T) {
	Convey("Sample correct", t, func() {
		var sample bytes.Buffer
		var cfg PathLengthConfig
		cfg.Sample(&sample, nil, nil)
		meta, err := toml.Decode(sample.String(), &cfg)
		cfg.InitDefaults()
		SoMsg("err", err, ShouldBeNil)
		SoMsg("unparsed", meta.Undecoded(), ShouldBeEmpty)

		SoMsg("AllowEmptyPaths correct", cfg.AllowEmptyPaths, ShouldBeTrue)
		SoMsg("DisallowPaths correct", cfg.DisallowPaths, ShouldBeFalse)
		SoMsg("MinPathlength correct", cfg.MinPathLength, ShouldEqual, 1)
		SoMsg("MaxPathLength correct", cfg.MaxPathLength, ShouldEqual, 2)
	})
}

func TestPathLengthConfig_Validate(t *testing.T) {
	Convey("Validation of a config should fail if", t, func() {

		Convey("Empty Paths not allowed and any paths disallowed", func() {
			err := makeConfig(false, true, 1, 4).Validate()
			So(err, ShouldNotBeNil)
		})
		Convey("Any paths disallowed and min path not zero", func() {
			err := makeConfig(true, true, 1, 0).Validate()
			So(err, ShouldNotBeNil)
		})
		Convey("Any paths disallowed and max path not zero", func() {
			err := makeConfig(true, true, 0, 4).Validate()
			So(err, ShouldNotBeNil)
		})

		Convey("Min Path length below 0", func() {
			err := makeConfig(false, false, -1, 4).Validate()
			So(err, ShouldNotBeNil)
		})
		Convey("Max Path length below 0", func() {
			err := makeConfig(false, false, 1, -3).Validate()
			So(err, ShouldNotBeNil)
		})
		Convey("Max Path length smaller than min path length", func() {
			err := makeConfig(false, false, 5, 4).Validate()
			So(err, ShouldNotBeNil)
		})
		Convey("Min Path length is zero", func() {
			err := makeConfig(true, false, 0, 4).Validate()
			So(err, ShouldNotBeNil)
		})
	})

	Convey("Validation of a config should not fail if", t, func() {

		Convey("If max path is smaller than min path length but zero", func() {
			err := makeConfig(false, false, 1, 0).Validate()
			So(err, ShouldBeNil)
		})
	})
}

func makeConfig(allowEmpty, disallowAny bool, min, max int) *PathLengthConfig {
	return &PathLengthConfig{
		AllowEmptyPaths: allowEmpty,
		DisallowPaths:   disallowAny,
		MinPathLength:   min,
		MaxPathLength:   max,
	}
}
