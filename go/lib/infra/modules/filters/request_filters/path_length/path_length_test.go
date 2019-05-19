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
	"github.com/scionproto/scion/go/lib/spath"
)

type pathCase struct {
	hops []uint8
}

var pathLengthTests = []struct {
	in          []pathCase
	result      bool
	description string
}{
	{
		[]pathCase{{[]uint8{1, 2}}, {[]uint8{3}}},
		false,
		"two segments",
	},
	{
		[]pathCase{{[]uint8{}}},
		false,
		"zero hopfields",
	},
	{
		[]pathCase{{[]uint8{1}}},
		false,
		"one hopfield",
	},
	{
		[]pathCase{{[]uint8{1, 2}}},
		true,
		"two hopfields",
	},
	{
		[]pathCase{{[]uint8{1, 2, 20}}},
		true,
		"length 2, starting from the front",
	},
	{
		[]pathCase{{[]uint8{1, 2, 3, 20, 21}}},
		false,
		"length 3, starting from the front",
	},
	{
		[]pathCase{{[]uint8{20, 1, 2}}},
		true,
		"length 2, starting from the back",
	},
	{
		[]pathCase{{[]uint8{20, 21, 1, 2, 3}}},
		false,
		"length 3, starting from the back",
	},
	{
		[]pathCase{{[]uint8{20, 21, 22, 23}}},
		false,
		"all verify only",
	},
}

func TestPathLengthOneFilter_pathLengthOne(t *testing.T) {

	Convey("Testing paths for path length one", t, func() {

		for _, c := range pathLengthTests {
			path := mkPathRevCase(c.in)
			Convey(fmt.Sprintf("A path with %v : %v", c.description, c.in), func() {
				isOne, err := pathLengthOne(path)

				Convey(fmt.Sprintf("Should return %v", c.result), func() {
					So(err, ShouldBeNil)
					So(isOne, ShouldEqual, c.result)
				})
			})
		}
	})
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
		ConsDir: false,
		TsInt:   0,
		ISD:     1,
		Hops:    uint8(len(pc.hops)),
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
