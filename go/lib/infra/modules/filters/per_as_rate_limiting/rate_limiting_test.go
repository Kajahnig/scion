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

package per_as_rate_limiting

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
)

var (
	IP1 = addr.HostFromIPStr("127.0.0.250")
	IP2 = addr.HostFromIPStr("127.0.0.251")

	IA1, _ = addr.IAFromString("2-ff00:0:211")

	IA1_IP1 = snet.SCIONAddress{IA: IA1, Host: IP1}
	IA1_IP2 = snet.SCIONAddress{IA: IA1, Host: IP2}

	path = &spath.Path{Raw: []byte("something")}
)

func TestPerASRateLimitFilter_FilterPacket(t *testing.T) {

	localConfigAS2maxCount3 := []string{nrOfLocalClients_flag, "2", localMaxCount_flag, "3", localInterval_flag, "300"}
	outsideConfigAS2maxCount3 := []string{nrOfOutsideASes_flag, "2", outsideMaxCount_flag, "3", outsideInterval_flag, "300"}
	bothConfigAS1localCount1OutsideCount2 := []string{nrOfLocalClients_flag, "1", localMaxCount_flag, "1", localInterval_flag, "300",
		nrOfOutsideASes_flag, "1", outsideMaxCount_flag, "2", outsideInterval_flag, "300"}

	Convey("Filtering packets with a per AS rate limit filter", t, func() {

		Convey("That does local but no external rate limiting", func() {

			var result filters.FilterResult

			localFilter, err := NewPerASRateLimitFilterFromStrings(localConfigAS2maxCount3)

			So(err, ShouldBeNil)

			localPacketFromOneIP := packetFrom(IA1_IP1, nil)
			for i := 0; i < 3; i++ {
				result, _ = localFilter.FilterPacket(localPacketFromOneIP)
			}

			Convey("Should accept a local packet from IP1 3 times, but not a 4th time", func() {
				So(result, ShouldEqual, filters.FilterAccept)
				result, _ = localFilter.FilterPacket(localPacketFromOneIP)
				So(result, ShouldEqual, filters.FilterDrop)
			})

			localPacketFromAnotherIP := packetFrom(IA1_IP2, nil)
			for i := 0; i < 3; i++ {
				result, _ = localFilter.FilterPacket(localPacketFromAnotherIP)
			}

			Convey("As it is local filtering, it should still accept another 3 packets from another local IP address", func() {
				So(result, ShouldEqual, filters.FilterAccept)
				result, _ = localFilter.FilterPacket(localPacketFromAnotherIP)
				So(result, ShouldEqual, filters.FilterDrop)
			})

			externalPacket := packetFrom(IA1_IP1, path) //because it has a path
			for i := 0; i < 5; i++ {
				result, _ = localFilter.FilterPacket(externalPacket)
			}

			Convey("But sending 5 packets form an outside AS should not be a problem, as there is no outside rate limiting", func() {
				So(result, ShouldEqual, filters.FilterAccept)
			})
		})

		Convey("That does external but no local rate limiting", func() {

			var result filters.FilterResult

			outsideFilter, err := NewPerASRateLimitFilterFromStrings(outsideConfigAS2maxCount3)

			So(err, ShouldBeNil)

			externalPacketFromOneIP := packetFrom(IA1_IP1, path)
			for i := 0; i < 3; i++ {
				result, _ = outsideFilter.FilterPacket(externalPacketFromOneIP)
			}

			Convey("Should accept an outside packet from IP1 3 times, but not a 4th time", func() {
				So(result, ShouldEqual, filters.FilterAccept)
				result, _ = outsideFilter.FilterPacket(externalPacketFromOneIP)
				So(result, ShouldEqual, filters.FilterDrop)
			})

			externalPacketFromSameIAButAnotherIP := packetFrom(IA1_IP2, path)

			Convey("As the filtering is per AS, the filter should not accept a packet from another IP of the same AS either", func() {
				result, _ = outsideFilter.FilterPacket(externalPacketFromSameIAButAnotherIP)
				So(result, ShouldEqual, filters.FilterDrop)
			})

			localPacket := packetFrom(IA1_IP1, nil) //because it has path nil
			for i := 0; i < 5; i++ {
				result, _ = outsideFilter.FilterPacket(localPacket)
			}

			Convey("But sending 5 packets form the local AS should be fine, as there is no local rate limiting", func() {
				So(result, ShouldEqual, filters.FilterAccept)
			})
		})

		Convey("That does local and external rate limiting", func() {

			var resultO1, resultO2, resultL1, resultL2 filters.FilterResult

			filter, err := NewPerASRateLimitFilterFromStrings(bothConfigAS1localCount1OutsideCount2)

			So(err, ShouldBeNil)

			outsidePacket := packetFrom(IA1_IP1, path)
			localPacket := packetFrom(IA1_IP1, nil)

			for i := 0; i < 2; i++ {
				resultO1, _ = filter.FilterPacket(outsidePacket)
			}

			resultO2, _ = filter.FilterPacket(outsidePacket)

			Convey("Should accept an outside packet from IP1 twice, but not a 3rd time", func() {
				So(resultO1, ShouldEqual, filters.FilterAccept)
				So(resultO2, ShouldEqual, filters.FilterDrop)
			})

			resultL1, _ = filter.FilterPacket(localPacket)
			resultL2, _ = filter.FilterPacket(localPacket)

			Convey("Should accept a local packet from IP1 once, but not a second time", func() {
				So(resultL1, ShouldEqual, filters.FilterAccept)
				So(resultL2, ShouldEqual, filters.FilterDrop)
			})
		})

	})
}

func TestPerASRateLimitFilter_FilterPacketWithResetIntevals(t *testing.T) {

	localConfig := []string{nrOfLocalClients_flag, "1", localMaxCount_flag, "2", localInterval_flag, "1"}

	Convey("Filtering packets with a per AS rate limit filter and 1 second reset intervals", t, func() {

		Convey("That does local rate limiting", func() {

			filter, err := NewPerASRateLimitFilterFromStrings(localConfig)
			So(err, ShouldBeNil)

			localPacket := packetFrom(IA1_IP1, nil)

			result1, err := filter.FilterPacket(localPacket)
			result2, err := filter.FilterPacket(localPacket)
			result3, err := filter.FilterPacket(localPacket)

			Convey("Should accept a local packet from IP1 twice, but not a 3rd time", func() {
				So(result1, ShouldEqual, filters.FilterAccept)
				So(result2, ShouldEqual, filters.FilterAccept)
				So(result3, ShouldEqual, filters.FilterDrop)
			})

			for result3 == filters.FilterDrop {
				result1 = result2
				result2 = result3
				result3, _ = filter.FilterPacket(localPacket)
			}

			Convey("After the filter has been reset, the local packets should be accepted again", func() {
				So(result1, ShouldEqual, filters.FilterDrop)
				So(result2, ShouldEqual, filters.FilterDrop)
				So(result3, ShouldEqual, filters.FilterAccept)
			})

			for i := 0; i < 2; i++ {
				result1 = result2
				result2 = result3
				result3, _ = filter.FilterPacket(localPacket)
			}

			Convey("And after sending another packet, the following packets should be dropped again", func() {
				So(result1, ShouldEqual, filters.FilterAccept)
				So(result2, ShouldEqual, filters.FilterAccept)
				So(result3, ShouldEqual, filters.FilterDrop)
			})

			for result3 == filters.FilterDrop {
				result1 = result2
				result2 = result3
				result3, _ = filter.FilterPacket(localPacket)
			}

			Convey("And after the filter is reset again the packets should be accepted again", func() {
				So(result1, ShouldEqual, filters.FilterDrop)
				So(result2, ShouldEqual, filters.FilterDrop)
				So(result3, ShouldEqual, filters.FilterAccept)
			})
		})
	})
}

func packetFrom(addr snet.SCIONAddress, path *spath.Path) *snet.SCIONPacket {
	return &snet.SCIONPacket{
		Bytes: nil,
		SCIONPacketInfo: snet.SCIONPacketInfo{
			Source: addr,
			Path:   path,
		},
	}
}
