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
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestCBFData8_GetMinimum(t *testing.T) {

	Convey("Getting the minimum out of", t, func() {
		tests := []struct {
			data                  []uint8
			locationsToChooseFrom []uint32
			minLocations          []uint32
			minValue              uint32
		}{
			{[]uint8{3}, []uint32{0}, []uint32{0}, 3},
			{[]uint8{1, 2, 3, 4, 5}, []uint32{3, 1, 0}, []uint32{0}, 1},
			{[]uint8{1, 2, 0, 4, 5}, []uint32{0, 0, 0}, []uint32{0, 0, 0}, 1},
			{[]uint8{1, 0, 5, 9, 1, 0, 0}, []uint32{3, 6, 1, 4}, []uint32{1, 6}, 0},
			{[]uint8{0, 0, 7, 1, 8, 0, 2, 0, 12}, []uint32{8, 6, 3, 4, 2}, []uint32{3}, 1},
			{[]uint8{0, 0, 7, 1, 8, 0, 2, 0, 13}, []uint32{0, 8, 1, 6, 7, 3, 5, 4, 2}, []uint32{5, 7, 1, 0}, 0},
		}

		for _, test := range tests {
			Convey(fmt.Sprintf("%v", test.data), func() {

				cbfData8 := &cbfData8{data: test.data}
				minLocations, minValue := cbfData8.getMinimum(test.locationsToChooseFrom)

				Convey(fmt.Sprintf("Should return minimum locations %v", test.minLocations), func() {
					So(minLocations, ShouldResemble, test.minLocations)
				})

				Convey(fmt.Sprintf("Should return minimum value %v", test.minValue), func() {
					So(minValue, ShouldEqual, test.minValue)
				})

			})
		}

	})
}

func TestCBFData8_IncreaseLocations(t *testing.T) {

	Convey("Increasing the values ", t, func() {
		tests := []struct {
			data                []uint8
			locationsToIncrease []uint32
			expectedDataState   []uint8
		}{
			{[]uint8{3},
				[]uint32{0},
				[]uint8{4}},
			{[]uint8{1, 2, 3, 4, 5},
				[]uint32{3, 1, 0},
				[]uint8{2, 3, 3, 5, 5}},
			{[]uint8{1, 2, 0, 4, 5}, []uint32{0, 0, 0},
				[]uint8{2, 2, 0, 4, 5}},
			{[]uint8{1, 0, 5, 9, 1, 0, 0},
				[]uint32{3, 6, 1, 4, 1, 3, 1},
				[]uint8{1, 1, 5, 10, 2, 0, 1}},
		}

		for _, test := range tests {

			cbfData8 := &cbfData8{data: test.data}

			Convey(fmt.Sprintf("of %v in the locations %v", test.data, test.locationsToIncrease), func() {

				cbfData8.increaseLocations(test.locationsToIncrease)

				Convey(fmt.Sprintf("Should result in %v", test.expectedDataState), func() {
					So(cbfData8.data, ShouldResemble, test.expectedDataState)
				})
			})
		}

	})
}

func TestCBFData8_reset(t *testing.T) {

	Convey("Resetting the array ", t, func() {
		tests := []struct {
			data []uint8
		}{
			{[]uint8{3}},
			{[]uint8{1, 2, 3, 4, 5}},
			{[]uint8{1, 2, 0, 4, 5}},
			{[]uint8{1, 0, 5, 9, 1, 0, 0}},
		}

		for _, test := range tests {

			cbfData8 := &cbfData8{data: test.data}

			Convey(fmt.Sprintf("%v", test.data), func() {

				cbfData8.reset()

				Convey(fmt.Sprintf("Should zero out the whole array"), func() {
					So(cbfData8.data, ShouldResemble, make([]uint8, len(cbfData8.data)))
				})
			})
		}

	})
}

func TestCBFData16_GetMinimum(t *testing.T) {

	Convey("Getting the minimum out of", t, func() {
		tests := []struct {
			data                  []uint16
			locationsToChooseFrom []uint32
			minLocations          []uint32
			minValue              uint32
		}{
			{[]uint16{3}, []uint32{0}, []uint32{0}, 3},
			{[]uint16{1, 2, 3, 4, 5}, []uint32{3, 1, 0}, []uint32{0}, 1},
			{[]uint16{1, 2, 0, 4, 5}, []uint32{0, 0, 0}, []uint32{0, 0, 0}, 1},
			{[]uint16{1, 0, 5, 9, 1, 0, 0}, []uint32{3, 6, 1, 4}, []uint32{1, 6}, 0},
			{[]uint16{0, 0, 7, 1, 8, 0, 2, 0, 12}, []uint32{8, 6, 3, 4, 2}, []uint32{3}, 1},
			{[]uint16{0, 0, 7, 1, 8, 0, 2, 0, 13}, []uint32{0, 8, 1, 6, 7, 3, 5, 4, 2}, []uint32{5, 7, 1, 0}, 0},
		}

		for _, test := range tests {
			Convey(fmt.Sprintf("%v", test.data), func() {

				cbfData16 := &cbfData16{data: test.data}
				minLocations, minValue := cbfData16.getMinimum(test.locationsToChooseFrom)

				Convey(fmt.Sprintf("Should return minimum locations %v", test.minLocations), func() {
					So(minLocations, ShouldResemble, test.minLocations)
				})

				Convey(fmt.Sprintf("Should return minimum value %v", test.minValue), func() {
					So(minValue, ShouldEqual, test.minValue)
				})

			})
		}

	})
}

func TestCBFData16_IncreaseLocations(t *testing.T) {

	Convey("Increasing the values ", t, func() {
		tests := []struct {
			data                []uint16
			locationsToIncrease []uint32
			expectedDataState   []uint16
		}{
			{[]uint16{3},
				[]uint32{0},
				[]uint16{4}},
			{[]uint16{1, 2, 3, 4, 5},
				[]uint32{3, 1, 0},
				[]uint16{2, 3, 3, 5, 5}},
			{[]uint16{1, 2, 0, 4, 5}, []uint32{0, 0, 0},
				[]uint16{2, 2, 0, 4, 5}},
			{[]uint16{1, 0, 5, 9, 1, 0, 0},
				[]uint32{3, 6, 1, 4, 1, 3, 1},
				[]uint16{1, 1, 5, 10, 2, 0, 1}},
		}

		for _, test := range tests {

			cbfData16 := &cbfData16{data: test.data}

			Convey(fmt.Sprintf("of %v in the locations %v", test.data, test.locationsToIncrease), func() {

				cbfData16.increaseLocations(test.locationsToIncrease)

				Convey(fmt.Sprintf("Should result in %v", test.expectedDataState), func() {
					So(cbfData16.data, ShouldResemble, test.expectedDataState)
				})
			})
		}

	})
}

func TestCBFData16_reset(t *testing.T) {
	Convey("Resetting the array ", t, func() {
		tests := []struct {
			data []uint16
		}{
			{[]uint16{3}},
			{[]uint16{1, 2, 3, 4, 5}},
			{[]uint16{1, 2, 0, 4, 5}},
			{[]uint16{1, 0, 5, 9, 1, 0, 0}},
		}

		for _, test := range tests {

			cbfData16 := &cbfData16{data: test.data}

			Convey(fmt.Sprintf("%v", test.data), func() {

				cbfData16.reset()

				Convey(fmt.Sprintf("Should zero out the whole array"), func() {
					So(cbfData16.data, ShouldResemble, make([]uint16, len(cbfData16.data)))
				})
			})
		}

	})
}
