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
	"github.com/scionproto/scion/go/border/braccept/tpkt"
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
)

func Test_NewPathLengthFilter(t *testing.T) {

	Convey("Creating a new filter", t, func() {

		tests := []struct {
			minPathLength int
			maxPathLength int
		}{
			{-1, 2},
			{3, -2},
			{1, 0},
		}

		for _, test := range tests {

			filter, err := NewPathLengthFilter(test.minPathLength, test.maxPathLength)

			Convey(fmt.Sprintf("With minlength %v and maxlength %v",
				test.minPathLength, test.maxPathLength), func() {

				Convey("Should return an error", func() {
					So(err, ShouldNotBeNil)
				})

				Convey("Should return nil instead of a filter", func() {
					So(filter, ShouldBeNil)
				})
			})
		}
	})

	Convey("Creating a new filter", t, func() {

		tests := []struct {
			minPathLength int
			maxPathLength int
		}{
			{0, 0},
			{0, 1},
			{1, 3},
		}

		for _, test := range tests {

			filter, err := NewPathLengthFilter(test.minPathLength, test.maxPathLength)

			Convey(fmt.Sprintf("With minlength %v and maxlength %v should not return an error",
				test.minPathLength, test.maxPathLength), func() {

				Convey("Should not return an error", func() {
					So(err, ShouldBeNil)
				})

				Convey("Should set the correct path lengths", func() {
					So(filter.minPathLength, ShouldEqual, test.minPathLength)
					So(filter.maxPathLength, ShouldEqual, test.maxPathLength)
				})
			})
		}
	})
}

func Test_NewPathLengthFilterFromStrings(t *testing.T) {

	Convey("Creating a path length filter with the strings", t, func() {

		tests := []struct {
			configString []string
			minLength    int
			maxLength    int
		}{
			{[]string{maxLength_flag, "3"},
				0, 3},
			{[]string{minLength_flag, "0", maxLength_flag, "0"},
				0, 0},
			{[]string{minLength_flag, "4", maxLength_flag, "5"},
				4, 5},
		}

		for _, test := range tests {

			Convey(strings.Join(test.configString, " "), func() {

				filter, err := NewPathLengthFilterFromStrings(test.configString)

				Convey("Should not return an error", func() {
					So(err, ShouldBeNil)
				})

				Convey(fmt.Sprintf("Should set min path length to %v", test.minLength), func() {
					So(filter.minPathLength, ShouldEqual, test.minLength)
				})

				Convey(fmt.Sprintf("Should set max path length to %v", test.maxLength), func() {
					So(filter.maxPathLength, ShouldEqual, test.maxLength)
				})
			})
		}
	})

	Convey("Creating a whitelisting filter with the strings", t, func() {

		tests := []struct {
			configString []string
		}{
			{[]string{minLength_flag, "3"}},
			{[]string{minLength_flag, "0", maxLength_flag, "-3"}},
			{[]string{minLength_flag, "-1", maxLength_flag, "2"}},
			{[]string{minLength_flag, "2", maxLength_flag, "1"}},
		}

		for _, test := range tests {

			Convey(strings.Join(test.configString, " "), func() {

				filter, err := NewPathLengthFilterFromStrings(test.configString)

				Convey("Should return an error and nil instead of a filter", func() {
					So(err, ShouldNotBeNil)
					So(filter, ShouldBeNil)
				})
			})
		}
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

		filter, _ := NewPathLengthFilter(0, 0)

		for _, c := range pathLengthTests {
			path := mkPathRevCase(c.in)
			Convey(fmt.Sprintf("With %v, path: %v\n", c.numberOfSegments, c.in), func() {
				pathLength, err := filter.determinePathLength(path)

				Convey("Should not return an error\n", func() {
					So(err, ShouldBeNil)
				})

				Convey(fmt.Sprintf("Should return the path length %v", c.resultingPathLength), func() {
					So(pathLength, ShouldEqual, c.resultingPathLength)
				})
			})
		}
	})
}

var pathOfLength2 = mkPathRevCase([]pathCase{{[]uint8{1, 2, 3}, false, false}})
var pathOfLength5 = mkPathRevCase([]pathCase{{[]uint8{1, 2, 3, 4, 5, 6}, false, false}})

var pathFilteringSettings = []struct {
	minPathLength int
	maxPathLength int
}{
	{0, 0},
	{0, 1},
	{1, 5},
	{6, 7},
}

var pathFilteringTests = []struct {
	path       *spath.Path
	pathLength int
	results    []filters.FilterResult
}{
	{nil, 0,
		[]filters.FilterResult{
			filters.FilterAccept,
			filters.FilterAccept,
			filters.FilterDrop,
			filters.FilterDrop}},
	{pathOfLength2, 2,
		[]filters.FilterResult{
			filters.FilterDrop,
			filters.FilterDrop,
			filters.FilterAccept,
			filters.FilterDrop}},
	{pathOfLength5, 5,
		[]filters.FilterResult{
			filters.FilterDrop,
			filters.FilterDrop,
			filters.FilterAccept,
			filters.FilterDrop}},
}

func Test_FilterPacket(t *testing.T) {

	for i, filterSettings := range pathFilteringSettings {

		Convey(fmt.Sprintf("Creating a path length filter with min path length %v and max path length %v",
			filterSettings.minPathLength, filterSettings.maxPathLength), t, func() {

			filter, _ := NewPathLengthFilter(filterSettings.minPathLength, filterSettings.maxPathLength)

			for _, test := range pathFilteringTests {

				packet := &snet.SCIONPacket{
					Bytes: nil,
					SCIONPacketInfo: snet.SCIONPacketInfo{
						Path: test.path,
					},
				}

				result, _ := filter.FilterPacket(packet)

				Convey(fmt.Sprintf("Filtering a path of length %v, should result in %v",
					test.pathLength, test.results[i].ToString()), func() {
					So(result, ShouldResemble, test.results[i])
				})
			}
		})
	}
}

func mkPathRevCase(in []pathCase) *spath.Path {
	segments := make([]*tpkt.Segment, 0)

	for _, seg := range in {
		segments = append(segments, makeSeg(seg))
	}

	path := tpkt.GenPath(0, 8, segments)
	return &path.Path
}

func makeSeg(pc pathCase) *tpkt.Segment {

	infoField := &spath.InfoField{
		ConsDir:  false,
		Shortcut: pc.shortcut,
		Peer:     pc.peeringShortcut,
		TsInt:    0,
		ISD:      1,
		Hops:     uint8(len(pc.hops)),
	}
	hopFields := make([]*spath.HopField, 0)
	for _, hopNr := range pc.hops {
		hopFields = append(hopFields, makeHopField(hopNr))
	}

	return tpkt.NewSegment(infoField, hopFields)
}

func makeHopField(hopNr uint8) *spath.HopField {
	return &spath.HopField{
		Xover:      hopNr >= 10 && hopNr < 20,
		VerifyOnly: hopNr >= 20,
	}
}
