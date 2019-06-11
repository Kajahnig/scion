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

package drkey_filter

import (
	"bytes"
	"testing"

	"github.com/BurntSushi/toml"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/scmp"
)

func TestDRKeyConfig_Sample(t *testing.T) {
	Convey("Sample correct", t, func() {
		var sample bytes.Buffer
		var cfg DRKeyConfig
		cfg.Sample(&sample, nil, nil)
		meta, err := toml.Decode(sample.String(), &cfg)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("unparsed", meta.Undecoded(), ShouldBeEmpty)

		SoMsg("Internal setting correct", cfg.InternalFiltering, ShouldBeTrue)
		SoMsg("External setting correct", cfg.ExternalFiltering, ShouldBeFalse)
		SoMsg("SCMP Types correct", cfg.SCMPTypesWithDRKey, ShouldResemble,
			[]scmp.ClassType{{Class: 0, Type: 2}, {Class: 3, Type: 0}})
	})
}

func TestDRKeyConfig_Validate(t *testing.T) {
	Convey("Validation of the config should fail if internal and external filtering is disabled", t, func() {
		cfg := DRKeyConfig{InternalFiltering: false, ExternalFiltering: false}
		err := cfg.Validate()

		SoMsg("Validation err should not be nil", err, ShouldNotBeNil)
	})
}