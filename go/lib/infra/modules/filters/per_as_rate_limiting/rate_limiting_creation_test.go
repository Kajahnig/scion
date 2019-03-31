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
	"fmt"
	"strings"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

var (
	emptyInfo  = &rateLimitFilterInfo{}
	faultyInfo = &rateLimitFilterInfo{
		interval: 20, numCells: 0,
		numHashFunc: 3, maxValue: 10}
	correctInfo1 = &rateLimitFilterInfo{
		interval: 20, numCells: 100,
		numHashFunc: 3, maxValue: 10}
	correctInfo2 = &rateLimitFilterInfo{
		interval: 20, numCells: 100,
		numHashFunc: 3, maxValue: 10}
)

func Test_calculateOptimalParameters(t *testing.T) {

	Convey("Calculating the optimal parameters", t, func() {
		tests := []struct {
			numOfElements         float64
			expectedNumOfCells    uint32
			expectedNumOfHashFunc uint32
		}{
			{1, 5, 3},
			{5, 24, 3},
			{9, 44, 3},
			{12, 58, 3},
			{19, 92, 3},
			{26, 125, 3},
		}
		for _, test := range tests {

			Convey(fmt.Sprintf("With %v elements to count for", test.numOfElements), func() {

				cells, hashFunc := calculateOptimalParameters(test.numOfElements)

				Convey(fmt.Sprintf("Should return %v cells and %v hash functions",
					test.expectedNumOfCells, test.expectedNumOfHashFunc), func() {

					So(cells, ShouldEqual, test.expectedNumOfCells)
					So(hashFunc, ShouldEqual, test.expectedNumOfHashFunc)
				})
			})
		}
	})
}

func Test_newRateLimitFilterInfo(t *testing.T) {

	Convey("Creating a new rate limit filter info ", t, func() {
		tests := []struct {
			interval      time.Duration
			numOfElements float64
			maxValue      uint32
		}{
			{0, 26, 5},
			{60, 26, 0},
			{60, 26, 65536},
			{60, 0, 5},
			{60, 26, 5},
		}
		for _, test := range tests[:4] {

			Convey(fmt.Sprintf("With interval %v, max value %v and %v elements",
				test.interval, test.maxValue, test.numOfElements), func() {

				_, err := newRateLimitFilterInfo(test.interval, test.numOfElements, test.maxValue)

				Convey("Should return an error", func() {
					So(err, ShouldNotBeNil)
				})
			})
		}

		for _, test := range tests[4:] {

			Convey(fmt.Sprintf("With interval %v, max value %v and %v elements",
				test.interval, test.maxValue, test.numOfElements), func() {

				info, err := newRateLimitFilterInfo(test.interval, test.numOfElements, test.maxValue)

				Convey("Should not return an error", func() {
					So(err, ShouldBeNil)
				})

				Convey(fmt.Sprintf("Should return an info with interval %v, max value %v, "+
					"%v cells and %v hash functions",
					test.interval, test.maxValue, 125, 3), func() {

					So(info.interval, ShouldEqual, test.interval)
					So(info.maxValue, ShouldEqual, test.maxValue)
					So(info.numCells, ShouldEqual, 125)
					So(info.numHashFunc, ShouldEqual, 3)
				})
			})
		}
	})
}

func TestNewPerASRateLimitFilter(t *testing.T) {

	Convey("Creating a new PerASRateLimitFilter", t, func() {

		tests := []struct {
			description string
			local       bool
			outside     bool
			localInfo   *rateLimitFilterInfo
			outsideInfo *rateLimitFilterInfo
		}{
			{"With no local and no outside filtering",
				false, false,
				emptyInfo, emptyInfo,
			},
			{"With faulty local filter info",
				true, true,
				faultyInfo, correctInfo2,
			},
			{"With faulty outside filter info",
				true, true,
				correctInfo1, faultyInfo,
			},
			{"With only local filter settings",
				true, false,
				correctInfo1, correctInfo2,
			},
			{"With only outside filter settings",
				false, true,
				correctInfo1, correctInfo2,
			},
			{"With local and outside filter settings",
				true, true,
				correctInfo1, correctInfo2,
			},
		}

		for _, test := range tests[0:3] {

			Convey(test.description, func() {

				_, err := NewPerASRateLimitFilter(test.local, test.outside, test.localInfo, test.outsideInfo)

				Convey("Should return an error", func() {
					So(err, ShouldNotBeNil)
				})
			})
		}
		for _, test := range tests[3:4] {
			Convey(test.description, func() {

				filter, err := NewPerASRateLimitFilter(test.local, test.outside, test.localInfo, test.outsideInfo)

				Convey("Should not return an error", func() {
					So(err, ShouldBeNil)
				})
				Convey("Should only initialize the local but not the outside cbf", func() {
					So(filter.localRateLimiting, ShouldBeTrue)
					So(filter.outsideRateLimiting, ShouldBeFalse)
					So(filter.localFilter, ShouldNotBeNil)
					So(filter.outsideFilter, ShouldBeNil)
				})
			})
		}
		for _, test := range tests[4:5] {
			Convey(test.description, func() {

				filter, err := NewPerASRateLimitFilter(test.local, test.outside, test.localInfo, test.outsideInfo)

				Convey("Should not return an error", func() {
					So(err, ShouldBeNil)
				})
				Convey("Should only initialize the outside but not the local cbf", func() {
					So(filter.localRateLimiting, ShouldBeFalse)
					So(filter.outsideRateLimiting, ShouldBeTrue)
					So(filter.localFilter, ShouldBeNil)
					So(filter.outsideFilter, ShouldNotBeNil)
				})
			})
		}
		for _, test := range tests[5:6] {
			Convey(test.description, func() {

				filter, err := NewPerASRateLimitFilter(test.local, test.outside, test.localInfo, test.outsideInfo)

				Convey("Should not return an error", func() {
					So(err, ShouldBeNil)
				})
				Convey("Should initialize the outside and the local cbf", func() {
					So(filter.localRateLimiting, ShouldBeTrue)
					So(filter.outsideRateLimiting, ShouldBeTrue)
					So(filter.localFilterInfo, ShouldResemble, *correctInfo1)
					So(filter.outsideFilterInfo, ShouldResemble, *correctInfo2)
					So(filter.localFilter, ShouldNotBeNil)
					So(filter.outsideFilter, ShouldNotBeNil)
				})
			})
		}
	})
}

func TestNewPerASRateLimitFilterFromStrings(t *testing.T) {

	Convey("Creating a per AS rate limiting filter from the strings", t, func() {

		testsWithErrors := []struct {
			configString []string
		}{
			{[]string{nrOfLocalClients_flag, "10", localInterval_flag, "0"}},
			{[]string{nrOfLocalClients_flag, "10", localMaxCount_flag, "70000"}},
			{[]string{nrOfOutsideASes_flag, "10", localInterval_flag, "60"}},
		}

		for _, test := range testsWithErrors {

			Convey(strings.Join(test.configString, " "), func() {

				_, err := NewPerASRateLimitFilterFromStrings(test.configString)

				Convey("Should return an error", func() {
					So(err, ShouldNotBeNil)
				})
			})
		}

		successfulTests := []struct {
			configString     []string
			expectedInterval time.Duration
			expectedMaxCount uint32
			local            bool
			outside          bool
		}{
			{[]string{nrOfLocalClients_flag, "10"},
				defaultInterval, defaultMaxCount,
				true, false},
			{[]string{nrOfLocalClients_flag, "10", localInterval_flag, "60", localMaxCount_flag, "300"},
				60 * time.Second, 300,
				true, false},
			{[]string{nrOfOutsideASes_flag, "10", outsideMaxCount_flag, "100"},
				defaultInterval, 100,
				false, true},
		}

		for _, test := range successfulTests {

			Convey(strings.Join(test.configString, " "), func() {

				filter, err := NewPerASRateLimitFilterFromStrings(test.configString)

				Convey("Should not return an error", func() {
					So(err, ShouldBeNil)
				})
				Convey(fmt.Sprintf("Should set the interval to %v, the number of cells to 48, "+
					"the number of hash functions to 3 and the max count to %v",
					test.expectedInterval, test.expectedMaxCount), func() {

					var info rateLimitFilterInfo
					if test.local {
						info = filter.localFilterInfo
					} else {
						info = filter.outsideFilterInfo
					}

					So(info.interval, ShouldEqual, test.expectedInterval)
					So(info.numCells, ShouldEqual, 48)
					So(info.numHashFunc, ShouldEqual, 3)
					So(info.maxValue, ShouldEqual, test.expectedMaxCount)
				})
				Convey("Should initialize correct cbf", func() {
					So(filter.localRateLimiting, ShouldEqual, test.local)
					So(filter.outsideRateLimiting, ShouldEqual, test.outside)
					if test.local {
						So(filter.localFilter, ShouldNotBeNil)
					} else {
						So(filter.localFilter, ShouldBeNil)
					}
					if test.outside {
						So(filter.outsideFilter, ShouldNotBeNil)
					} else {
						So(filter.outsideFilter, ShouldBeNil)
					}
				})
			})
		}

		configStringWithBothSettings := []string{nrOfLocalClients_flag, "20", nrOfOutsideASes_flag, "30"}

		Convey(strings.Join(configStringWithBothSettings, " "), func() {

			filter, err := NewPerASRateLimitFilterFromStrings(configStringWithBothSettings)

			Convey("Should not return an error", func() {
				So(err, ShouldBeNil)
			})
			Convey(fmt.Sprintf("Should set the intervals and max counts to the default value, "+
				"the number of cells for the local filter to 96, for the outside filter to 144"), func() {

				localInfo := filter.localFilterInfo
				outsideInfo := filter.outsideFilterInfo

				So(localInfo.interval, ShouldEqual, defaultInterval)
				So(localInfo.numCells, ShouldEqual, 96)
				So(localInfo.numHashFunc, ShouldEqual, 3)
				So(localInfo.maxValue, ShouldEqual, defaultMaxCount)

				So(outsideInfo.interval, ShouldEqual, defaultInterval)
				So(outsideInfo.numCells, ShouldEqual, 144)
				So(outsideInfo.numHashFunc, ShouldEqual, 3)
				So(outsideInfo.maxValue, ShouldEqual, defaultMaxCount)
			})
			Convey("Should initialize both cbfs", func() {
				So(filter.localRateLimiting, ShouldBeTrue)
				So(filter.outsideRateLimiting, ShouldBeTrue)
				So(filter.localFilter, ShouldNotBeNil)
				So(filter.outsideFilter, ShouldNotBeNil)
			})
		})
	})
}
