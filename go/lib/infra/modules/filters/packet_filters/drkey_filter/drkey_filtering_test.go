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

package drkey_filter

import (
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spse/scmp_auth"
)

func TestDRKeyFilter_FilterPacket(t *testing.T) {
	//UDP Packet without extension
	//	if internal packet,
	// 		internal filtering set -> drop
	//		internal filtering not set -> accept
	//	if external packet,
	// 		external filtering set -> drop
	// 		external filtering not set -> accept
	//SCMP packet
	//	without extension
	//		type not on mandatory list -> accept
	//		type on mandatory list -> drop
	//	with extension
	//		type not on mandatory list -> accept
	//		TODO type on mandatory list -> check extension
	//UDP Packet with extension
	// 	TODO internal Packet
	// 		if extension valid, accept else drop
	// 	TODO external Packet
	// 		if extension valid, accept else drop

	internalFilter := &DRKeyFilter{true, false, [][]bool{{true}}}
	externalFilter := &DRKeyFilter{false, true, [][]bool{{false}}}

	Convey("Filtering UDP packets without a DRKey extension", t, func() {
		path := &spath.Path{Raw: make(common.RawBytes, 10)}
		internalPacket := SCIONPacketWithPathAndHdr(nil, &l4.UDP{}, nil)
		externalPacket := SCIONPacketWithPathAndHdr(path, &l4.UDP{}, nil)

		Convey("With a drkey filter that only filters internal packets", func() {
			result1, _ := internalFilter.FilterPacket(internalPacket)
			result2, _ := internalFilter.FilterPacket(externalPacket)

			Convey("Should drop the internal packet and accept the external one", func() {
				So(result1, ShouldEqual, filters.FilterDrop)
				So(result2, ShouldEqual, filters.FilterAccept)
			})
		})
		Convey("With a drkey filter that only filters external packets", func() {
			result1, _ := externalFilter.FilterPacket(internalPacket)
			result2, _ := externalFilter.FilterPacket(externalPacket)

			Convey("Should drop the internal packet and accept the external one", func() {
				So(result1, ShouldEqual, filters.FilterAccept)
				So(result2, ShouldEqual, filters.FilterDrop)
			})
		})
	})

	filter := &DRKeyFilter{true, true,
		[][]bool{{true, false}}}

	Convey("Filtering SCMP packets", t, func() {
		ext := &scmp_auth.DRKeyExtn{}
		mandatorySCMPWithoutExt := SCIONPacketWithPathAndHdr(nil, &scmp.Hdr{Class: 0, Type: 0}, nil)
		nonMandatorySCMPWithExt := SCIONPacketWithPathAndHdr(nil, &scmp.Hdr{Class: 0, Type: 1}, ext)
		nonMandatorySCMPWithoutExt := SCIONPacketWithPathAndHdr(nil, &scmp.Hdr{Class: 0, Type: 1}, nil)

		Convey("Without an extension", func() {
			result1, _ := filter.FilterPacket(mandatorySCMPWithoutExt)
			result2, _ := filter.FilterPacket(nonMandatorySCMPWithoutExt)

			Convey("Should drop the mandatory packet and let the non mandatory one pass", func() {
				So(result1, ShouldEqual, filters.FilterDrop)
				So(result2, ShouldEqual, filters.FilterAccept)
			})
		})

		Convey("With an extension", func() {
			result1, _ := filter.FilterPacket(nonMandatorySCMPWithExt)

			Convey("Should accept the non mandatory packet", func() {
				So(result1, ShouldEqual, filters.FilterAccept)
			})
		})
	})
}

func SCIONPacketWithPathAndHdr(path *spath.Path, l4 l4.L4Header, extension common.Extension) *snet.SCIONPacket {
	if extension == nil {
		return &snet.SCIONPacket{
			Bytes: nil,
			SCIONPacketInfo: snet.SCIONPacketInfo{
				Extensions: []common.Extension{},
				Path:       path,
				L4Header:   l4,
			},
		}
	}
	return &snet.SCIONPacket{
		Bytes: nil,
		SCIONPacketInfo: snet.SCIONPacketInfo{
			Extensions: []common.Extension{extension},
			Path:       path,
			L4Header:   l4,
		},
	}
}

func Test_extractDirAndMac(t *testing.T) {

	tests := []struct {
		dir scmp_auth.Dir
		mac common.RawBytes
	}{
		{scmp_auth.AsToAs, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
		{scmp_auth.HostToAs, []byte{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}},
	}

	for _, test := range tests {

		Convey(fmt.Sprintf("Extracting dir %v and MAC %v from a filter packet", test.dir, test.mac), t, func() {

			extension1 := scmp_auth.NewDRKeyExtn()
			err := extension1.SetDirection(test.dir)
			Convey("Should not throw an error when setting the dir", func() {
				So(err, ShouldBeNil)
			})

			err = extension1.SetMAC(test.mac)
			Convey("Should not throw an error when setting the mac", func() {
				So(err, ShouldBeNil)
			})

			pkt := &snet.SCIONPacket{
				Bytes: nil,
				SCIONPacketInfo: snet.SCIONPacketInfo{
					Extensions: []common.Extension{
						extension1,
					},
				},
			}

			dir, mac, err := extractDirAndMac(pkt)

			Convey("Should not return an error", func() {
				So(err, ShouldBeNil)
			})

			Convey("Should return the dir that was set", func() {
				So(dir, ShouldResemble, test.dir)
			})

			Convey("Should return the MAC that was set", func() {
				So(mac, ShouldResemble, test.mac)
			})

		})
	}

	Convey("Extracting dir and MAC from a filter packet without DRKey extension", t, func() {

		pkt := &snet.SCIONPacket{
			Bytes: nil,
			SCIONPacketInfo: snet.SCIONPacketInfo{
				Extensions: []common.Extension{},
			},
		}

		dir, mac, err := extractDirAndMac(pkt)

		Convey("Should not return an error", func() {
			So(err, ShouldBeNil)
		})

		Convey("Should return the default dir", func() {
			So(dir, ShouldResemble, scmp_auth.Dir(0))
		})

		Convey("Should return nil instead of a mac", func() {
			So(mac, ShouldBeNil)
		})

	})
}
