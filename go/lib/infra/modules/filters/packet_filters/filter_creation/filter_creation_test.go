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
	"fmt"
	"reflect"
	"testing"

	"github.com/BurntSushi/toml"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/infra/modules/filters/packet_filters/drkey_filter"
)

func TestCreateFiltersFromConfig(t *testing.T) {
	Convey("Creating filters from a config file with all filters", t, func() {

		var cfg PacketFilterConfig
		_, err := toml.DecodeFile("./test_config.toml", &cfg)

		Convey("Should not return an error when decoding the file", func() {
			So(err, ShouldBeNil)
		})

		cfg.InitDefaults()
		validErr := cfg.Validate()

		Convey("Should not return a validation error", func() {
			So(validErr, ShouldBeNil)
		})

		filterSlice, err := CreateFiltersFromConfig(cfg)

		Convey("Should not return an error when creating the filters", func() {
			So(err, ShouldBeNil)
		})

		Convey("Should return a filled filter slice", func() {
			So(filterSlice, ShouldHaveLength, 1)
		})

		tests := []struct {
			typeDescription string
			filterType      reflect.Type
		}{
			{"DRKey Source Auth Filter",
				reflect.TypeOf(&drkey_filter.DRKeyFilter{})},
		}

		for i, test := range tests {

			Convey(fmt.Sprintf("The %v. filter in the slice should be a %v", i+1, test.typeDescription), func() {
				So(reflect.TypeOf(*filterSlice[i]), ShouldEqual, test.filterType)
			})
		}
	})

}
