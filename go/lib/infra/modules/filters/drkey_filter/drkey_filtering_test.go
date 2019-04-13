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
	"github.com/scionproto/scion/bazel-scion/external/go_sdk/src/fmt"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/snet"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/spse/scmp_auth"
)

func TestDRKeyFilter_FilterPacket(t *testing.T) {
	//TODO: implement when missing functions are implemented
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
}
