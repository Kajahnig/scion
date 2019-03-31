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

package counting_bloom

import (
	"fmt"
	"reflect"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestNewCBF(t *testing.T) {

	Convey("Creating a CBF with", t, func() {
		errorTests := []struct {
			explanation string
			numCells    uint32
			numHashes   uint32
			maxValue    uint32
		}{
			{"0 cells",
				0, 2, 3},
			{"0 hash functions",
				1, 0, 3},
			{"0 as a maximum value",
				3, 5, 0},
			{"A maximum value bigger than 16 bit",
				10, 4, 65536},
		}

		for _, test := range errorTests {
			Convey(test.explanation, func() {

				_, err := NewCBF(test.numCells, test.numHashes, test.maxValue)

				Convey("Should return an error", func() {
					So(err, ShouldNotBeNil)
				})
			})
		}
		tests := []struct {
			maxValue    uint32
			cbfDataType reflect.Type
			typeString  string
		}{
			{255, reflect.TypeOf(&cbfData8{}), "8"},
			{256, reflect.TypeOf(&cbfData16{}), "16"},
		}

		for _, test := range tests {
			Convey(fmt.Sprintf("A maximum value of %v", test.maxValue), func() {

				cbf, err := NewCBF(10, 3, test.maxValue)

				Convey("Should not return an error", func() {
					So(err, ShouldBeNil)
				})

				Convey(fmt.Sprintf("Should return a CBF with %v bit cbfData", test.typeString), func() {
					So(reflect.TypeOf(cbf.filter1), ShouldEqual, test.cbfDataType)
					So(reflect.TypeOf(cbf.filter2), ShouldEqual, test.cbfDataType)
				})
			})
		}
	})
}

func TestCBF_CheckIfRateLimitExceeded(t *testing.T) {

	Convey("Creating a new CBF with 5 cells, 3 hash functions and max value 4", t, func() {
		cbf, err := NewCBF(5, 3, 4)

		Convey("Should not return an error", func() {
			So(err, ShouldBeNil)
		})

		var answer = true
		var err2 error
		for i := 0; i < 4; i++ {
			answer, err2 = cbf.CheckIfRateLimitExceeded([]byte("hello"))
		}

		Convey("Checking for an exceeded rate limit for 4 times should return false and no error", func() {
			So(err2, ShouldBeNil)
			So(answer, ShouldBeFalse)
		})

		Convey("Checking for an exceeded rate limit for a 5th time should return true and no error", func() {
			answer, err2 := cbf.CheckIfRateLimitExceeded([]byte("hello"))
			So(err2, ShouldBeNil)
			So(answer, ShouldBeTrue)
		})

	})

	Convey("Creating a new CBF with 15 cells, 3 hash functions and max value 2", t, func() {
		cbf, err := NewCBF(15, 3, 2)

		Convey("Should not return an error", func() {
			So(err, ShouldBeNil)
		})

		answer1, err1 := cbf.CheckIfRateLimitExceeded([]byte("key1"))
		answer2, err2 := cbf.CheckIfRateLimitExceeded([]byte("key2"))
		answer3, err3 := cbf.CheckIfRateLimitExceeded([]byte("key3"))
		answer4, err4 := cbf.CheckIfRateLimitExceeded([]byte("key2"))
		answer5, err5 := cbf.CheckIfRateLimitExceeded([]byte("key1"))

		Convey("Adding key1 and key2 twice, and key3 once should always return false and no error", func() {
			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)
			So(err3, ShouldBeNil)
			So(err4, ShouldBeNil)
			So(err5, ShouldBeNil)
			So(answer1, ShouldBeFalse)
			So(answer2, ShouldBeFalse)
			So(answer3, ShouldBeFalse)
			So(answer4, ShouldBeFalse)
			So(answer5, ShouldBeFalse)
		})

		Convey("Checking for an exceeded rate limit for key1 again should return true", func() {
			answer6, err6 := cbf.CheckIfRateLimitExceeded([]byte("key1"))
			So(err6, ShouldBeNil)
			So(answer6, ShouldBeTrue)
		})
		Convey("Checking for an exceeded rate limit for key3 again should return false", func() {
			answer7, err7 := cbf.CheckIfRateLimitExceeded([]byte("key3"))
			So(err7, ShouldBeNil)
			So(answer7, ShouldBeFalse)
		})
	})
}

func TestCBF_Reset(t *testing.T) {

	cbf, err := NewCBF(5, 3, 1)

	Convey("Creating a new CBF with 5 cells, 3 hash functions and max value 1", t, func() {
		So(err, ShouldBeNil)

		answer1, _ := cbf.CheckIfRateLimitExceeded([]byte("key1"))
		answer2, _ := cbf.CheckIfRateLimitExceeded([]byte("key1"))

		Convey("Checking for an exceeded rate limit for key1 should return false the first and true the second time", func() {
			So(answer1, ShouldBeFalse)
			So(answer2, ShouldBeTrue)
		})

		cbf.Reset()

		answer1, _ = cbf.CheckIfRateLimitExceeded([]byte("key1"))
		answer2, _ = cbf.CheckIfRateLimitExceeded([]byte("key1"))

		Convey("Calling reset and repeating that should have the same effect", func() {
			So(answer1, ShouldBeFalse)
			So(answer2, ShouldBeTrue)
		})

		cbf.Reset()

		answer1, _ = cbf.CheckIfRateLimitExceeded([]byte("key1"))
		answer2, _ = cbf.CheckIfRateLimitExceeded([]byte("key1"))

		Convey("Also for the second reset call", func() {
			So(answer1, ShouldBeFalse)
			So(answer2, ShouldBeTrue)
		})
	})
}

func Test_getHashes(t *testing.T) {

	Convey("Creating a new CBF", t, func() {
		cbf, err := NewCBF(5, 3, 4)

		Convey("Should not return an error", func() {
			So(err, ShouldBeNil)
		})

		h11, h21, err1 := cbf.getHashes([]byte("hello1"))
		h12, h22, err2 := cbf.getHashes([]byte("hello1"))
		h13, h23, err3 := cbf.getHashes([]byte("hello2"))

		Convey("Getting hashes for the same key twice should return no error and the same values", func() {
			So(h11, ShouldEqual, h12)
			So(h21, ShouldEqual, h22)
			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)
		})

		Convey("Getting hashes for a different key should return no error and different values", func() {
			So(h11, ShouldNotEqual, h13)
			So(h21, ShouldNotEqual, h23)
			So(err3, ShouldBeNil)
		})
	})
}
