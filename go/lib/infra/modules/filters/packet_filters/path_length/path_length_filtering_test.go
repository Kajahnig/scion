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

package path_length

import (
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
)

func TestNewPathLengthFilterFromConfig(t *testing.T) {

	Convey("Creating a new filter from a config", t, func() {

		filter, err := NewPathLengthFilterFromConfig(
			&PathLengthConfig{
				MinPathLength: -1,
				MaxPathLength: 2})

		Convey("Should return an error for an invalid config and a nil for the filter", func() {
			So(err, ShouldNotBeNil)
			So(filter, ShouldBeNil)
		})

		filter, err = NewPathLengthFilterFromConfig(
			&PathLengthConfig{
				MinPathLength: 5,
				MaxPathLength: 10})

		Convey("Should set the correct path lengths", func() {
			So(filter.minPathLength, ShouldEqual, 5)
			So(filter.maxPathLength, ShouldEqual, 10)
		})

	})
}

type pathCase struct {
	hops            []uint8
	shortcut        bool
	peeringShortcut bool
}

var pathLengthTests = []struct {
	in                  []pathCase
	resultingPathLength int
	numberOfSegments    string
}{
	// 1 segment, 2 hops    case 1c/1d from the book
	{
		[]pathCase{{[]uint8{1, 2}, false, false}},
		1,
		"1 segment",
	},
	// 1 segment, 5 hops 	case 1c/1d from the book
	{
		[]pathCase{{[]uint8{1, 2, 3, 4, 5}, false, false}},
		4,
		"1 segment",
	},
	// 2 segments, 5 hops	case 1b/1e from the book
	{
		[]pathCase{{[]uint8{1, 12}, false, false},
			{[]uint8{3, 4, 5}, false, false}},
		3,
		"2 segments",
	},
	// 3 segments, 9 hops	case 1a from the book
	{
		[]pathCase{
			{[]uint8{1, 12}, false, false},
			{[]uint8{3, 4, 5, 16}, false, false},
			{[]uint8{7, 8, 9}, false, false},
		},
		6,
		"3 segments",
	},
	// case 2 from the book : peering shortcut
	{
		[]pathCase{{[]uint8{1, 12, 23}, false, true},
			{[]uint8{24, 15, 6}, false, true}},
		3,
		"a peering shortcut",
	},
	// case 3 from the book: non peering shortcut
	{
		[]pathCase{{[]uint8{1, 12, 23}, true, false},
			{[]uint8{24, 15, 6}, true, false}},
		2,
		"a non peering shortcut",
	},
	// case 4 from the book: on path
	{
		[]pathCase{{[]uint8{1, 2, 3, 24, 25}, false, false}},
		2,
		"on-path destination AS",
	},
}

func Test_determinePathLength(t *testing.T) {

	Convey("Determining the path length of a path", t, func() {

		for _, c := range pathLengthTests {
			path := mkPathRevCase(c.in)
			Convey(fmt.Sprintf("With %v, path: %v\n", c.numberOfSegments, c.in), func() {
				pathLength, err := determinePathLength(path)

				Convey("Should not return an error\n", func() {
					So(err, ShouldBeNil)
				})

				Convey(fmt.Sprintf("Should return the path length %v", c.resultingPathLength), func() {
					So(pathLength, ShouldEqual, c.resultingPathLength)
				})
			})
		}
	})

	Convey("Determining the path length of a path without hop fields", t, func() {

		pathLength, err := determinePathLength(pathWith0HopFields)

		Convey("Should not return an error\n", func() {
			So(err, ShouldBeNil)
		})

		Convey("Should not return true for is empty", func() {
			So(pathWith0HopFields.IsEmpty(), ShouldBeFalse)
		})

		Convey("Should return the path length -1", func() {
			So(pathLength, ShouldEqual, -1)
		})
	})

	Convey("Determining the path length of a path with one hop field", t, func() {

		pathLength, err := determinePathLength(pathWith1HopField)

		Convey("Should not return an error\n", func() {
			So(err, ShouldBeNil)
		})

		Convey("Should not return true for is empty", func() {
			So(pathWith1HopField.IsEmpty(), ShouldBeFalse)
		})

		Convey("Should return the path length 0", func() {
			So(pathLength, ShouldEqual, 0)
		})
	})
}

var pathWith0HopFields = mkPathRevCase([]pathCase{{[]uint8{}, false, false}})
var pathWith1HopField = mkPathRevCase([]pathCase{{[]uint8{1}, false, false}})
var pathOfLength2 = mkPathRevCase([]pathCase{{[]uint8{1, 2, 3}, false, false}})
var pathOfLength5 = mkPathRevCase([]pathCase{{[]uint8{1, 2, 3, 4, 5, 6}, false, false}})

var pathFilteringSettings = []struct {
	allowEmptyPath bool
	disallowPath   bool
	minPathLength  int
	maxPathLength  int
}{
	{true, true, 0, 0},
	{false, false, 1, 0},
	{false, false, 1, 4},
	{true, false, 5, 7},
}

var pathFilteringTests = []struct {
	path        *spath.Path
	description string
	results     []filters.FilterResult
}{
	{nil, "an empty path",
		[]filters.FilterResult{
			filters.FilterAccept,
			filters.FilterDrop,
			filters.FilterDrop,
			filters.FilterAccept}},
	{pathWith0HopFields, "a non-empty path with 0 hop fields",
		[]filters.FilterResult{
			filters.FilterDrop,
			filters.FilterDrop,
			filters.FilterDrop,
			filters.FilterDrop}},
	{pathWith1HopField, "a non-empty path with 1 hop field",
		[]filters.FilterResult{
			filters.FilterDrop,
			filters.FilterDrop,
			filters.FilterDrop,
			filters.FilterDrop}},
	{pathOfLength2, "a path of length 2",
		[]filters.FilterResult{
			filters.FilterDrop,
			filters.FilterAccept,
			filters.FilterAccept,
			filters.FilterDrop}},
	{pathOfLength5, "a path of length 5",
		[]filters.FilterResult{
			filters.FilterDrop,
			filters.FilterAccept,
			filters.FilterDrop,
			filters.FilterAccept}},
}

func Test_FilterPacket(t *testing.T) {

	for i, filterSettings := range pathFilteringSettings {

		Convey(fmt.Sprintf("Creating a path length filter with min path length %v and max path length %v",
			filterSettings.minPathLength, filterSettings.maxPathLength), t, func() {

			filter := &PathLengthFilter{
				filterSettings.allowEmptyPath, filterSettings.disallowPath,
				filterSettings.minPathLength, filterSettings.maxPathLength}

			for _, test := range pathFilteringTests {

				packet := &snet.SCIONPacket{
					Bytes: nil,
					SCIONPacketInfo: snet.SCIONPacketInfo{
						Path: test.path,
					},
				}

				result, _ := filter.FilterPacket(packet)

				Convey(fmt.Sprintf("Filtering %v, should result in %v",
					test.description, test.results[i].ToString()), func() {
					So(result, ShouldResemble, test.results[i])
				})
			}
		})
	}
}

func mkPathRevCase(in []pathCase) *spath.Path {
	path := &spath.Path{InfOff: 0, HopOff: 0}
	plen := 0
	for _, seg := range in {
		plen += spath.InfoFieldLength + len(seg.hops)*spath.HopFieldLength
	}
	path.Raw = make(common.RawBytes, plen)
	offset := 0
	for _, seg := range in {
		makeSeg(path.Raw[offset:], seg)
		offset += spath.InfoFieldLength + len(seg.hops)*spath.HopFieldLength
	}
	return path
}

func makeSeg(b common.RawBytes, pc pathCase) {
	infoField := &spath.InfoField{
		ConsDir:  false,
		Shortcut: pc.shortcut,
		Peer:     pc.peeringShortcut,
		TsInt:    0,
		ISD:      1,
		Hops:     uint8(len(pc.hops)),
	}
	infoField.Write(b)

	for i, hop := range pc.hops {
		hopField := makeHopField(hop)
		hopField.Write(b[spath.InfoFieldLength+i*spath.HopFieldLength:])
	}

	hopFields := make([]*spath.HopField, 0)
	for _, hopNr := range pc.hops {
		hopFields = append(hopFields, makeHopField(hopNr))
	}
}

func makeHopField(hopNr uint8) *spath.HopField {
	return &spath.HopField{
		Xover:      hopNr >= 10 && hopNr < 20,
		VerifyOnly: hopNr >= 20,
	}
}
