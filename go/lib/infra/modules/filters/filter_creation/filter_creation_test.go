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
	"github.com/scionproto/scion/go/lib/infra/modules/filters/path_length"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/whitelisting"
	"reflect"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func Test_NewPathLengthFilterFromStrings(t *testing.T) {

	Convey("Creating a whitelisting filter from the string", t, func() {

		tests := []struct {
			configString string
			filterType   reflect.Type
		}{
			{"whitelist -path ../whitelisting/test_topology.json -outside ISD",
				reflect.TypeOf(whitelisting.WhitelistFilter{})},
			{"pathLength -max",
				reflect.TypeOf(path_length.PathLengthFilter{})},
		}

		for _, test := range tests {

			Convey(test.configString, func() {

				filter, err, add := createFilter(test.configString)

				Convey("Should not return an error and add should be true", func() {
					So(err, ShouldBeNil)
					So(add, ShouldBeTrue)
				})

				Convey("Should return a filter of type %v", func() {
					So(filter, ShouldHaveSameTypeAs, test.filterType)
				})

			})
		}

	})
}

// TODO test create Filter
//should return whitelisting filter on whitelist flag
//should return path length filter on path length flag

// TODO testCreateFiltersFromConfigFile
//should take a file and create filters in correct order
