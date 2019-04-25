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
	"fmt"
	"io"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/per_as_rate_limiting"
)

const whitelistRescanningSample = `
#Rescanning intervals for the equivalent whitelist filters
Infra = "10ms"
Neighbours = "1s"
Up = "3m"
Down = "5h"
Core = "23h"
`
const intervalRequestLimitingSampleInternal = `
[IntervalRequestLimiting.Internal]
`
const intervalRequestLimitingSampleExternal = `
[IntervalRequestLimiting.External]
`
const requestConfigSampleName1 = `
[RequestConfigs.TRCRequest]
`
const requestConfigSampleName2 = `
[RequestConfigs.ChainRequest]
`

var (
	defaultWLInterval = duration{24 * time.Hour}
)

var _ config.Config = (*FilterHandlerConfig)(nil)

type FilterHandlerConfig struct {
	WhitelistRescanning struct {
		Infra      duration
		Neighbours duration
		Up         duration
		Down       duration
		Core       duration
	}
	IntervalRequestLimiting struct {
		Internal *per_as_rate_limiting.RateLimitConfig
		External *per_as_rate_limiting.RateLimitConfig
	}

	RequestConfigs map[string]RequestConfig
}

func (cfg *FilterHandlerConfig) InitDefaults() {
	cfg.initWhitelistDefaults()

	if cfg.IntervalRequestLimiting.Internal != nil {
		cfg.IntervalRequestLimiting.Internal.InitDefaults()
	}
	if cfg.IntervalRequestLimiting.External != nil {
		cfg.IntervalRequestLimiting.External.InitDefaults()
	}
}

func (cfg *FilterHandlerConfig) initWhitelistDefaults() {

	if cfg.WhitelistRescanning.Infra.Duration == 0 {
		cfg.WhitelistRescanning.Infra = defaultWLInterval
	}
	if cfg.WhitelistRescanning.Neighbours.Duration == 0 {
		cfg.WhitelistRescanning.Neighbours = defaultWLInterval
	}
	if cfg.WhitelistRescanning.Up.Duration == 0 {
		cfg.WhitelistRescanning.Up = defaultWLInterval
	}
	if cfg.WhitelistRescanning.Down.Duration == 0 {
		cfg.WhitelistRescanning.Down = defaultWLInterval
	}
	if cfg.WhitelistRescanning.Core.Duration == 0 {
		cfg.WhitelistRescanning.Core = defaultWLInterval
	}
}

func (cfg FilterHandlerConfig) Validate() error {

	if err := cfg.validateWhitelist(); err != nil {
		return err
	}
	if cfg.IntervalRequestLimiting.Internal != nil {
		if err := cfg.IntervalRequestLimiting.Internal.Validate(); err != nil {
			return err
		}
	}
	if cfg.IntervalRequestLimiting.External != nil {
		if err := cfg.IntervalRequestLimiting.External.Validate(); err != nil {
			return err
		}
	}
	for _, rcfg := range cfg.RequestConfigs {
		if err := rcfg.Validate(); err != nil {
			return err
		}
		if rcfg.InternalRateLimit == IntervalRL && cfg.IntervalRequestLimiting.Internal == nil {
			return common.NewBasicError("Request config specifies internal "+
				"interval request limiting but filter config is missing", nil)
		}
		if rcfg.ExternalRateLimit == IntervalRL && cfg.IntervalRequestLimiting.External == nil {
			return common.NewBasicError("Request config specifies external "+
				"interval request limiting but filter config is missing", nil)
		}
	}
	return nil
}

func (cfg FilterHandlerConfig) validateWhitelist() error {

	errorString := "%v whitelist rescanning interval is negative"

	if cfg.WhitelistRescanning.Infra.Duration < 0 {
		return common.NewBasicError(fmt.Sprintf(errorString, "Infra"), nil)
	}
	if cfg.WhitelistRescanning.Neighbours.Duration < 0 {
		return common.NewBasicError(fmt.Sprintf(errorString, "Neighbours"), nil)
	}
	if cfg.WhitelistRescanning.Up.Duration < 0 {
		return common.NewBasicError(fmt.Sprintf(errorString, "Up"), nil)
	}
	if cfg.WhitelistRescanning.Down.Duration < 0 {
		return common.NewBasicError(fmt.Sprintf(errorString, "Down"), nil)
	}
	if cfg.WhitelistRescanning.Core.Duration < 0 {
		return common.NewBasicError(fmt.Sprintf(errorString, "Core"), nil)
	}
	return nil
}

func (cfg FilterHandlerConfig) ConfigName() string {
	return "filterHandler"
}

func (cfg FilterHandlerConfig) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteSample(dst, path, ctx,
		config.StringSampler{
			Text: whitelistRescanningSample,
			Name: "WhitelistRescanning",
		},
		config.StringSampler{
			Text: intervalRequestLimitingSampleInternal + per_as_rate_limiting.RateLimitSample +
				intervalRequestLimitingSampleExternal + per_as_rate_limiting.RateLimitSample,
			Name: "IntervalRequestLimiting",
		},
		config.StringSampler{
			Text: requestConfigSampleName1 + requestConfigSample +
				requestConfigSampleName2 + requestConfigSample,
			Name: "RequestConfigs",
		},
	)
}

type duration struct {
	time.Duration
}

func (d *duration) UnmarshalText(text []byte) error {
	var err error
	d.Duration, err = time.ParseDuration(string(text))
	return err
}
