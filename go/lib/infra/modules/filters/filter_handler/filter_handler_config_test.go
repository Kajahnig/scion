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

package filter_handler

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/infra/modules/filters/request_filters/interval_request_limiting"
)

func TestFilterHandlerConfig_Sample(t *testing.T) {
	Convey("Sample correct", t, func() {
		var sample bytes.Buffer
		var cfg FilterHandlerConfig
		cfg.Sample(&sample, nil, nil)
		meta, err := toml.Decode(sample.String(), &cfg)
		SoMsg("Decoding err", err, ShouldBeNil)
		err = cfg.Validate()
		SoMsg("Vaidation err", err, ShouldBeNil)
		SoMsg("unparsed", meta.Undecoded(), ShouldBeEmpty)

		//Whitelist rescanning
		SoMsg("Infra WL rescanning interval correct", cfg.WhitelistRescanning.Infra.Duration,
			ShouldEqual, 10*time.Millisecond)
		SoMsg("Neighbours WL rescanning interval correct", cfg.WhitelistRescanning.Neighbours.Duration,
			ShouldEqual, 1*time.Second)
		SoMsg("Up WL rescanning interval correct", cfg.WhitelistRescanning.Up.Duration,
			ShouldEqual, 3*time.Minute)
		SoMsg("Down WL rescanning interval correct", cfg.WhitelistRescanning.Down.Duration,
			ShouldEqual, 5*time.Hour)
		SoMsg("Core  WL rescanning interval correct", cfg.WhitelistRescanning.Core.Duration,
			ShouldEqual, 23*time.Hour)
		//interval request limiting
		checkIntervalRequestLimit("Internal", cfg.IntervalRequestLimiting.Internal)
		checkIntervalRequestLimit("External", cfg.IntervalRequestLimiting.External)
		//request configs
		SoMsg("Should contain request config for TRCReq", cfg.RequestConfigs["TRCRequest"], ShouldNotBeNil)
		checkRequestConfig(cfg.RequestConfigs["TRCRequest"])
		SoMsg("Should contain request config for ChainReq", cfg.RequestConfigs["ChainRequest"], ShouldNotBeNil)
		checkRequestConfig(cfg.RequestConfigs["ChainRequest"])
	})
}

func checkIntervalRequestLimit(location string, config *interval_request_limiting.RateLimitConfig) {
	SoMsg(fmt.Sprintf("%v Interval RL: Number of clients correct", location), config.NumOfClients,
		ShouldEqual, 100)
	SoMsg(fmt.Sprintf("%v Interval RL: Interval correct", location), config.Interval.Duration,
		ShouldEqual, 20*time.Second)
	SoMsg(fmt.Sprintf("%v Interval RL: Max count correct", location), config.MaxCount,
		ShouldEqual, 5)
}

func checkRequestConfig(cfg RequestConfig) {
	SoMsg("Internal WL setting correct", cfg.InternalWL, ShouldEqual, InfraWL)
	SoMsg("External WL setting correct", cfg.ExternalWL, ShouldEqual, ISDWL)
	SoMsg("Internal rate limit setting correct", cfg.InternalRateLimit, ShouldEqual, IntervalRL)
	SoMsg("External rate limit setting correct", cfg.ExternalRateLimit, ShouldEqual, HistoryRL)
}
