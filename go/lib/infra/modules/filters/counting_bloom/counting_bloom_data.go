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
	getMinimum(locations []uint32) (minLocations []uint32, minValue uint32)
	increaseLocations(minLocations []uint32)
	reset()
}

var _ cbfData = (*cbfData8)(nil)

type cbfData8 struct {
	data []uint8
}

func (c *cbfData8) getMinimum(locations []uint32) ([]uint32, uint32) {
	values := make([]uint8, len(locations))

	var minValue = c.data[locations[0]]
	values[0] = minValue
	var counter = 1

	for i, location := range locations[1:] {
		value := c.data[location]
		if value < minValue {
			minValue = value
			counter = 1
		} else if value == minValue {
			counter++
		}
		values[i+1] = value
	}

	minLocations := make([]uint32, counter)

	for i, value := range values {
		if value == minValue {
			minLocations[counter-1] = locations[i]
			counter--
		}
	}
	return minLocations, uint32(minValue)
}

func (c *cbfData8) increaseLocations(minLocations []uint32) {
	for i, location := range minLocations {
		alreadyIncreased := false
		for _, prevLocation := range minLocations[:i] {
			if prevLocation == location {
				alreadyIncreased = true
			}
		}
		if !alreadyIncreased {
			c.data[location] += 1
		}
	}
}

func (c *cbfData8) reset() {
	for i, _ := range c.data {
		c.data[i] = 0
	}
}

var _ cbfData = (*cbfData16)(nil)

type cbfData16 struct {
	data []uint16
}

func (c *cbfData16) getMinimum(locations []uint32) ([]uint32, uint32) {
	values := make([]uint16, len(locations))

	var minValue = c.data[locations[0]]
	values[0] = minValue
	var counter = 1

	for i, location := range locations[1:] {
		value := c.data[location]
		if value < minValue {
			minValue = value
			counter = 1
		} else if value == minValue {
			counter++
		}
		values[i+1] = value
	}

	minLocations := make([]uint32, counter)

	for i, value := range values {
		if value == minValue {
			minLocations[counter-1] = locations[i]
			counter--
		}
	}
	return minLocations, uint32(minValue)
}

func (c *cbfData16) increaseLocations(minLocations []uint32) {
	for i, location := range minLocations {
		alreadyIncreased := false
		for _, prevLocation := range minLocations[:i] {
			if prevLocation == location {
				alreadyIncreased = true
			}
		}
		if !alreadyIncreased {
			c.data[location] += 1
		}
	}
}

func (c *cbfData16) reset() {
	for i, _ := range c.data {
		c.data[i] = 0
	}
}
