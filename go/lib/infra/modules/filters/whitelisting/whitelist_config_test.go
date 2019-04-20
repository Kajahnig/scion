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
	"bytes"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	. "github.com/smartystreets/goconvey/convey"
)

func TestWhitelistConfig_Sample(t *testing.T) {
	Convey("Sample correct", t, func() {
		var sample bytes.Buffer
		var cfg WhitelistConfig
		cfg.Sample(&sample, nil, nil)
		meta, err := toml.Decode(sample.String(), &cfg)
		cfg.InitDefaults()
		cfg.Validate()
		SoMsg("err", err, ShouldBeNil)
		SoMsg("unparsed", meta.Undecoded(), ShouldBeEmpty)

		SoMsg("Path to topology file correct", cfg.PathToTopoFile, ShouldEqual, "../whitelisting/topology.json")
		SoMsg("Rescanning interval correct", cfg.RescanInterval.Duration, ShouldEqual, 40*time.Minute)
		SoMsg("Outside WL setting correct", cfg.OutsideWLSetting.OutsideWLSetting, ShouldEqual, WLISD)
		SoMsg("Local WL setting correct", cfg.LocalWLSetting.LocalWLSetting, ShouldEqual, WLLocalInfraNodes)
	})
}

func TestWhitelistConfig_Validate(t *testing.T) {
	Convey("Validation of a config should fail if", t, func() {

		Convey("Invalid path to topology file", func() {
			err := makeConfig("invalid/path", time.Second, WLISD, WLLocalInfraNodes).Validate()
			So(err, ShouldNotBeNil)
		})
		Convey("Rescanning interval is negative", func() {
			err := makeConfig("./topology.json", -1*time.Second, WLISD, WLLocalInfraNodes).Validate()
			So(err, ShouldNotBeNil)
		})
		Convey("Local and outside whitelisting are set to no whitelisting", func() {
			err := makeConfig("./topology.json", time.Second, NoOutsideWL, NoLocalWL).Validate()
			So(err, ShouldNotBeNil)
		})
	})
}

func TestWhitelistConfig_InitDefaults(t *testing.T) {
	Convey("Initialising defaults should", t, func() {

		cfg := &WhitelistConfig{
			PathToTopoFile:   "./toplogy.json",
			OutsideWLSetting: outsideSetting{WLISD},
			LocalWLSetting:   localSetting{WLLocalAS},
		}

		cfg.InitDefaults()

		Convey("Set the rescan intervals to the default value", func() {
			So(cfg.RescanInterval.Duration, ShouldEqual, defaultRescanningInterval)
		})
	})
}

func makeConfig(path string, interval time.Duration, osetting OutsideWLSetting,
	lsetting LocalWLSetting) *WhitelistConfig {
	return &WhitelistConfig{
		PathToTopoFile:   path,
		RescanInterval:   duration{interval},
		OutsideWLSetting: outsideSetting{osetting},
		LocalWLSetting:   localSetting{lsetting},
	}
}
