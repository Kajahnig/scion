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
		Convey(fmt.Sprintf("With interval %v, max value %v and %v elements",
			60, 5, 26), func() {

			info, err := newRateLimitFilterInfo(60, 26, 5)

			Convey("Should not return an error", func() {
				So(err, ShouldBeNil)
			})

			Convey("Should return a correct filter info", func() {

				So(info.interval, ShouldEqual, 60)
				So(info.maxValue, ShouldEqual, 5)
				So(info.numCells, ShouldEqual, 125)
				So(info.numHashFunc, ShouldEqual, 3)
			})
		})
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

				_, err := newPerASRateLimitFilter(test.local, test.outside, test.localInfo, test.outsideInfo)

				Convey("Should return an error", func() {
					So(err, ShouldNotBeNil)
				})
			})
		}
		for _, test := range tests[3:4] {
			Convey(test.description, func() {

				filter, err := newPerASRateLimitFilter(test.local, test.outside, test.localInfo, test.outsideInfo)

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

				filter, err := newPerASRateLimitFilter(test.local, test.outside, test.localInfo, test.outsideInfo)

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

				filter, err := newPerASRateLimitFilter(test.local, test.outside, test.localInfo, test.outsideInfo)

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

func TestNewPerASRateLimitFilterFromConfig(t *testing.T) {
	cfg := &PerASRateLimitConfig{
		LocalClients:    10,
		OutsideASes:     5,
		LocalInterval:   duration{5 * time.Minute},
		OutsideInterval: duration{10 * time.Minute},
		LocalMaxCount:   20,
		OutsideMaxCount: 50,
	}

	Convey("Creating a per AS rate limiting filter from a configuration", t, func() {

		filter, err := NewPerASRateLimitingFilterFromConfig(cfg)

		Convey("Should not return an error", func() {
			So(err, ShouldBeNil)
		})

		Convey("Should no return nil instead of a filter", func() {
			So(filter, ShouldNotBeNil)
		})

		Convey("Should initialize the fields with the correct values", func() {
			So(filter.localRateLimiting, ShouldBeTrue)
			So(filter.outsideRateLimiting, ShouldBeTrue)
			So(filter.localFilterInfo.interval, ShouldEqual, 5*time.Minute)
			So(filter.localFilterInfo.maxValue, ShouldEqual, 20)
			So(filter.localFilterInfo.numCells, ShouldEqual, 48)
			So(filter.localFilterInfo.numHashFunc, ShouldEqual, 3)
			So(filter.outsideFilterInfo.interval, ShouldEqual, 10*time.Minute)
			So(filter.outsideFilterInfo.maxValue, ShouldEqual, 50)
			So(filter.outsideFilterInfo.numCells, ShouldEqual, 24)
			So(filter.outsideFilterInfo.numHashFunc, ShouldEqual, 3)
		})
	})
}
