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

type cbfData interface {
	getMinimum(locations []int) (minLocations []int, minValue int)
	increaseLocations(minLocations []int)
	reset()
}

var _ cbfData = (*cbfData8)(nil)

type cbfData8 struct {
	data []uint8
}

func (c *cbfData8) getMinimum(locations []int) (minLocations []int, minValue int) {

	minLocations = make([]int, 1, len(locations))
	minLocations[0] = locations[0]

	minVal := c.data[locations[0]]

	for _, location := range locations[1:] {
		value := c.data[location]
		if value < minVal {
			minVal = value
			minLocations = minLocations[len(minLocations):]
			minLocations = append(minLocations, location)
		} else if value == minVal {
			minLocations = append(minLocations, location)
		}
	}

	return minLocations, int(minVal)
}

func (c *cbfData8) increaseLocations(minLocations []int) {
	for _, location := range minLocations {
		c.data[location] += 1
	}
}

func (c *cbfData8) reset() {
	for i := range c.data {
		c.data[i] = 0
	}
}

var _ cbfData = (*cbfData16)(nil)

type cbfData16 struct {
	data []uint16
}

func (c *cbfData16) getMinimum(locations []int) (minLocations []int, minValue int) {
	minLocations = make([]int, 1, len(locations))
	minLocations[0] = locations[0]

	minVal := c.data[locations[0]]

	for _, location := range locations[1:] {
		value := c.data[location]
		if value < minVal {
			minVal = value
			minLocations = minLocations[len(minLocations):]
			minLocations = append(minLocations, location)
		} else if value == minVal {
			minLocations = append(minLocations, location)
		}
	}

	return minLocations, int(minVal)

}

func (c *cbfData16) increaseLocations(minLocations []int) {
	for _, location := range minLocations {
		c.data[location] += 1
	}
}

func (c *cbfData16) reset() {
	for i := range c.data {
		c.data[i] = 0
	}
}
