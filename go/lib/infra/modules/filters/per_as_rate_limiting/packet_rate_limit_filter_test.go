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

func TestNewPacketRateLimitingFilterFromConfig(t *testing.T) {

	rateLimitConfig := &RateLimitConfig{
		NumOfClients: 10,
		MaxCount:     20,
	}

	Convey("Creating a new packet rate limit filter with a local config", t, func() {

		cfg := &PacketRateLimitConfig{
			LocalConfig:   rateLimitConfig,
			OutsideConfig: nil,
		}
		cfg.InitDefaults()

		filter, err := NewPacketRateLimitingFilterFromConfig(cfg)

		Convey("Should not return an error", func() {
			So(err, ShouldBeNil)
		})
		Convey("Should initialise the local rate limit filter with the correct values", func() {
			So(filter.localRateLimitFilter.numCells, ShouldEqual, 48)
			So(filter.localRateLimitFilter.numHashFunc, ShouldEqual, 3)
			So(filter.localRateLimitFilter.maxValue, ShouldEqual, 20)
		})
		Convey("Should set the outside filter to nil", func() {
			So(filter.outsideRateLimitFilter, ShouldBeNil)
		})
	})

	Convey("Creating a new packet rate limit filter with an outside config", t, func() {

		cfg := &PacketRateLimitConfig{
			LocalConfig:   nil,
			OutsideConfig: rateLimitConfig,
		}
		cfg.InitDefaults()

		filter, err := NewPacketRateLimitingFilterFromConfig(cfg)

		Convey("Should not return an error", func() {
			So(err, ShouldBeNil)
		})
		Convey("Should initialise the outside rate limit filter with the correct values", func() {
			So(filter.outsideRateLimitFilter.numCells, ShouldEqual, 48)
			So(filter.outsideRateLimitFilter.numHashFunc, ShouldEqual, 3)
			So(filter.outsideRateLimitFilter.maxValue, ShouldEqual, 20)
		})
		Convey("Should set the local filter to nil", func() {
			So(filter.localRateLimitFilter, ShouldBeNil)
		})
	})

	Convey("Creating a new packet rate limit filter with local and outside configs", t, func() {

		cfg := &PacketRateLimitConfig{
			LocalConfig:   rateLimitConfig,
			OutsideConfig: rateLimitConfig,
		}
		cfg.InitDefaults()

		filter, err := NewPacketRateLimitingFilterFromConfig(cfg)

		Convey("Should not return an error", func() {
			So(err, ShouldBeNil)
		})
		Convey("Should set neither of the filters to nil", func() {
			So(filter.localRateLimitFilter, ShouldNotBeNil)
			So(filter.outsideRateLimitFilter, ShouldNotBeNil)
		})
	})

	Convey("Creating a new packet rate limit filter with neither local nor outside configs", t, func() {

		cfg := &PacketRateLimitConfig{
			LocalConfig:   nil,
			OutsideConfig: nil,
		}
		cfg.InitDefaults()

		_, err := NewPacketRateLimitingFilterFromConfig(cfg)

		Convey("Should return an error", func() {
			So(err, ShouldNotBeNil)
		})
	})

	Convey("Creating a new packet rate limit filter a faulty config", t, func() {

		cfg := &PacketRateLimitConfig{
			LocalConfig: &RateLimitConfig{
				NumOfClients: -10,
			},
			OutsideConfig: nil,
		}
		cfg.InitDefaults()

		_, err := NewPacketRateLimitingFilterFromConfig(cfg)

		Convey("Should return an error", func() {
			So(err, ShouldNotBeNil)
		})
	})
}

func TestPerASRateLimitFilter_FilterPacket(t *testing.T) {

	rateLimitConfig := &RateLimitConfig{NumOfClients: 2, MaxCount: 3}

	localConfigAS2maxCount3 := &PacketRateLimitConfig{LocalConfig: rateLimitConfig}
	outsideConfigAS2maxCount3 := &PacketRateLimitConfig{OutsideConfig: rateLimitConfig}

	localConfig := &RateLimitConfig{NumOfClients: 1, MaxCount: 1}
	localConfig.InitDefaults()
	outsideConfig := &RateLimitConfig{NumOfClients: 1, MaxCount: 2}
	outsideConfig.InitDefaults()

	bothConfigAS1localCount1OutsideCount2 := &PacketRateLimitConfig{localConfig, outsideConfig}

	localConfigAS2maxCount3.InitDefaults()
	outsideConfigAS2maxCount3.InitDefaults()
	bothConfigAS1localCount1OutsideCount2.InitDefaults()

	Convey("Filtering packets with a per AS rate limit filter", t, func() {

		Convey("That does local but no external rate limiting", func() {

			var result filters.FilterResult

			localFilter, err := NewPacketRateLimitingFilterFromConfig(localConfigAS2maxCount3)

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

			outsideFilter, err := NewPacketRateLimitingFilterFromConfig(outsideConfigAS2maxCount3)

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

			filter, err := NewPacketRateLimitingFilterFromConfig(bothConfigAS1localCount1OutsideCount2)

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

func packetFrom(addr snet.SCIONAddress, path *spath.Path) *snet.SCIONPacket {
	return &snet.SCIONPacket{
		Bytes: nil,
		SCIONPacketInfo: snet.SCIONPacketInfo{
			Source: addr,
			Path:   path,
		},
	}
}
