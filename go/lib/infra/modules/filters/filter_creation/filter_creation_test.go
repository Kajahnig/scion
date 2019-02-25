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

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/infra/modules/filters/path_length"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/whitelisting"
)

func Test_createFilter(t *testing.T) {

	Convey("Creating a filter from the string", t, func() {

		tests := []struct {
			configString    string
			configDirString string
			filterType      reflect.Type
			typeDescription string
		}{
			{"whitelist -path ../whitelisting/test_topology.json -outside ISD",
				".",
				reflect.TypeOf(&whitelisting.WhitelistFilter{}),
				"Whitelist Filter"},
			{"whitelist -outside ISD",
				"../whitelisting",
				reflect.TypeOf(&whitelisting.WhitelistFilter{}),
				"Whitelist Filter"},
			{"pathLength -max 3",
				".",
				reflect.TypeOf(&path_length.PathLengthFilter{}),
				"Path Length Filter"},
		}

		for _, test := range tests {

			Convey(test.configString+"\n and configDir "+test.configDirString, func() {

				filter, err, add := createFilter(test.configString, test.configDirString)
				Convey("Should not return an error", func() {
					So(err, ShouldBeNil)
				})

				Convey("Should return true for add", func() {
					So(add, ShouldBeTrue)
				})

				Convey(fmt.Sprintf("Should return a %v", test.typeDescription), func() {
					So(reflect.TypeOf(*filter), ShouldEqual, test.filterType)
				})
			})
		}

		nilFilterTests := []struct {
			configString string
			isError      bool
		}{
			{"// comment with multiple words", false},
			{"     ", false}, //line with only whitespaces
			{"nonExistentFilter", true},
			{"whitelist -invalidFlag", true},
			{"pathLength -invalidFlag", true},
		}

		for _, test := range nilFilterTests {

			Convey(test.configString, func() {

				filter, err, add := createFilter(test.configString, ".")

				if test.isError {
					Convey("Should return an error", func() {
						So(err, ShouldNotBeNil)
					})
				} else {
					Convey("Should not return an error", func() {
						So(err, ShouldBeNil)
					})
				}

				Convey("Should return false for add", func() {
					So(add, ShouldBeFalse)
				})

				Convey("Should return nil instead of a filter", func() {
					So(filter, ShouldBeNil)
				})
			})
		}
	})
}

func Test_CreateFiltersFromConfigFile(t *testing.T) {

	Convey("Creating filters", t, func() {

		tests := []struct {
			configFileDescription string
			configDirString       string
			nameOfConfigFile      string
		}{
			{"With a non existent file as file name input",
				".",
				"nonexistentFileName"},
			{"With an nonexistentPath as configDir input",
				"./nonexistentFolder/anotherOne",
				"test_config"},
			{"From a config file containing an error",
				".",
				"faulty_test_config"},
		}

		for _, test := range tests {

			Convey(test.configFileDescription, func() {

				filterSlice, err := CreateFiltersFromConfigFile(test.configDirString, test.nameOfConfigFile)

				Convey("Should return an error", func() {
					So(err, ShouldNotBeNil)
				})

				Convey("Should return an empty filter slice", func() {
					So(filterSlice, ShouldBeNil)
				})
			})
		}
	})

	Convey("Creating filters from a config file with all filters", t, func() {

		filterSlice, err := CreateFiltersFromConfigFile(".", "test_config")

		Convey("Should not return an error", func() {
			So(err, ShouldBeNil)
		})

		Convey("Should return a filled filter slice", func() {
			So(filterSlice, ShouldHaveLength, 2)
		})

		tests := []struct {
			typeDescription string
			filterType      reflect.Type
		}{
			{"Whitelist Filter",
				reflect.TypeOf(&whitelisting.WhitelistFilter{})},
			{"Path Length Filter",
				reflect.TypeOf(&path_length.PathLengthFilter{})},
		}

		for i, test := range tests {

			Convey(fmt.Sprintf("The %v. filter in the slice should be a %v", i+1, test.typeDescription), func() {
				So(reflect.TypeOf(*filterSlice[i]), ShouldEqual, test.filterType)
			})
		}
	})
}
