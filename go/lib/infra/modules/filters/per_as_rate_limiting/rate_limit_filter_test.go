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

	"github.com/scionproto/scion/go/lib/infra/modules/filters"
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

func TestRateLimitFilter_filterFromConfig(t *testing.T) {
	cfg := &RateLimitConfig{
		NumOfClients: 10,
		Interval:     duration{5 * time.Minute},
		MaxCount:     20,
	}

	Convey("Creating a rate limiting filter from a configuration", t, func() {

		filter, err := FilterFromConfig(cfg)

		Convey("Should not return an error", func() {
			So(err, ShouldBeNil)
		})

		Convey("Should not return nil instead of a filter", func() {
			So(filter, ShouldNotBeNil)
		})

		Convey("Should initialize the fields with the correct values", func() {
			So(filter.maxValue, ShouldEqual, 20)
			So(filter.numCells, ShouldEqual, 48)
			So(filter.numHashFunc, ShouldEqual, 3)
			So(filter.filter, ShouldNotBeNil)
		})
	})

	Convey("Creating a rate limiting filter from a nil configuration", t, func() {

		filter, err := FilterFromConfig(nil)

		Convey("Should not return an error", func() {
			So(err, ShouldBeNil)
		})

		Convey("Should return nil instead of a filter", func() {
			So(filter, ShouldBeNil)
		})
	})
}

func TestRateLimitFilter_checkLimit(t *testing.T) {
	cfg := &RateLimitConfig{
		NumOfClients: 1,
		Interval:     duration{5 * time.Minute},
		MaxCount:     1,
	}

	Convey("Checking the limit on a rate limit filter with max count 1", t, func() {

		filter, err := FilterFromConfig(cfg)
		So(err, ShouldBeNil)
		So(filter, ShouldNotBeNil)

		result, err := filter.checkLimit([]byte("hello"))

		Convey("Should not return an error", func() {
			So(err, ShouldBeNil)
		})

		Convey("Should return FilterAccept for the first call", func() {
			So(result, ShouldEqual, filters.FilterAccept)
		})

		result, err = filter.checkLimit([]byte("hello"))

		Convey("Should return FilterDrop for the second call", func() {
			So(err, ShouldBeNil)
			So(result, ShouldEqual, filters.FilterDrop)
		})
	})
}

func TestRateLimitFilter_filterReset(t *testing.T) {
	cfg := &RateLimitConfig{
		NumOfClients: 1,
		Interval:     duration{10 * time.Millisecond},
		MaxCount:     2,
	}

	Convey("Checking the limit on a rate limit filter with max count 2", t, func() {

		filter, err := FilterFromConfig(cfg)
		So(err, ShouldBeNil)
		So(filter, ShouldNotBeNil)

		packet := []byte("hello")

		result1, _ := filter.checkLimit(packet)
		result2, _ := filter.checkLimit(packet)
		result3, _ := filter.checkLimit(packet)

		Convey("Should accept a value twice, but not a 3rd time", func() {
			So(result1, ShouldEqual, filters.FilterAccept)
			So(result2, ShouldEqual, filters.FilterAccept)
			So(result3, ShouldEqual, filters.FilterDrop)
		})

		for result3 == filters.FilterDrop {
			result1 = result2
			result2 = result3
			result3, _ = filter.checkLimit(packet)
		}

		Convey("After the filter has been reset, the value should be accepted again", func() {
			So(result1, ShouldEqual, filters.FilterDrop)
			So(result2, ShouldEqual, filters.FilterDrop)
			So(result3, ShouldEqual, filters.FilterAccept)
		})

		for i := 0; i < 2; i++ {
			result1 = result2
			result2 = result3
			result3, _ = filter.checkLimit(packet)
		}

		Convey("And after checking the limits for the value agian, the following checks should be dropped again", func() {
			So(result1, ShouldEqual, filters.FilterAccept)
			So(result2, ShouldEqual, filters.FilterAccept)
			So(result3, ShouldEqual, filters.FilterDrop)
		})

		for result3 == filters.FilterDrop {
			result1 = result2
			result2 = result3
			result3, _ = filter.checkLimit(packet)
		}

		Convey("And after the filter is reset again the value should be accepted again", func() {
			So(result1, ShouldEqual, filters.FilterDrop)
			So(result2, ShouldEqual, filters.FilterDrop)
			So(result3, ShouldEqual, filters.FilterAccept)
		})
	})
}
