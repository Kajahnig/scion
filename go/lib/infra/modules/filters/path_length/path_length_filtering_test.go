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
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
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

	Convey("Creating a whitelisting filter with the strings", t, func() {

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
	consDir bool
	hops    []uint8
}

var pathLengthTests = []struct {
	in                  []pathCase
	inOffs              [][2]int
	resultingPathLength int
	numberOfSegments    string
}{
	// 1 segment, 2 hops
	{
		[]pathCase{{true, []uint8{11, 12}}},
		[][2]int{{0, 8}, {0, 16}},
		1,
		"1 segment",
	},
	// 1 segment, 5 hops
	{
		[]pathCase{{true, []uint8{11, 12, 13, 14, 15}}},
		[][2]int{{0, 24}, {0, 32}},
		4,
		"1 segment",
	},
	// 2 segments, 5 hops
	{
		[]pathCase{{true, []uint8{11, 12}}, {false, []uint8{13, 14, 15}}},
		[][2]int{{0, 8}, {24, 48}},
		3,
		"2 segments",
	},
	// 3 segments, 9 hops
	{
		[]pathCase{
			{true, []uint8{11, 12}},
			{false, []uint8{13, 14, 15, 16}},
			{false, []uint8{17, 18, 19}},
		},
		[][2]int{
			{0, 8}, {24, 40}, {64, 88},
		},
		6,
		"3 segments",
	},
}

func Test_determinePathLength(t *testing.T) {

	Convey("Determining the path length of a path", t, func() {

		filter, _ := NewPathLengthFilter(0, 0)

		for _, c := range pathLengthTests {
			for j := range c.inOffs {
				path := mkPathRevCase(c.in, c.inOffs[j][0], c.inOffs[j][1])
				Convey(fmt.Sprintf("With %v, info field offset %v and hop field offset %v",
					c.numberOfSegments, path.InfOff, path.HopOff), func() {

					pathLength, err := filter.determinePathLength(path)

					Convey("Should not return an error", func() {
						So(err, ShouldBeNil)
					})

					Convey("Should return the correct path length", func() {
						So(pathLength, ShouldEqual, c.resultingPathLength)
					})
				})
			}
		}
	})
}

var pathOfLength2 = mkPathRevCase([]pathCase{{true, []uint8{11, 12, 13}}}, 0, 8)
var pathOfLength5 = mkPathRevCase([]pathCase{{true, []uint8{11, 12, 13, 14, 15, 16}}}, 0, 32)

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

func mkPathRevCase(in []pathCase, inInfOff, inHopfOff int) *spath.Path {
	path := &spath.Path{InfOff: inInfOff, HopOff: inHopfOff}
	plen := 0
	for _, seg := range in {
		plen += spath.InfoFieldLength + len(seg.hops)*spath.HopFieldLength
	}
	path.Raw = make(common.RawBytes, plen)
	offset := 0
	for i, seg := range in {
		makeSeg(path.Raw[offset:], seg.consDir, uint16(i), seg.hops)
		offset += spath.InfoFieldLength + len(seg.hops)*spath.HopFieldLength
	}
	return path
}

func makeSeg(b common.RawBytes, consDir bool, isd uint16, hops []uint8) {
	infof := spath.InfoField{ConsDir: consDir, ISD: isd, Hops: uint8(len(hops))}
	infof.Write(b)
	for i, hop := range hops {
		for j := 0; j < spath.HopFieldLength; j++ {
			b[spath.InfoFieldLength+i*spath.HopFieldLength+j] = hop
		}
	}
}
