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
	"io"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/config"
)

var _ config.Config = (*PacketRateLimitConfig)(nil)

type PacketRateLimitConfig struct {
	LocalConfig   *RateLimitConfig
	OutsideConfig *RateLimitConfig
}

func (cfg *PacketRateLimitConfig) InitDefaults() {
	if cfg.LocalConfig != nil {
		cfg.LocalConfig.InitDefaults()
	}
	if cfg.OutsideConfig != nil {
		cfg.OutsideConfig.InitDefaults()
	}
}

func (cfg PacketRateLimitConfig) Validate() error {
	if cfg.LocalConfig != nil {
		err := cfg.LocalConfig.Validate()
		if err != nil {
			return err
		}
	}

	if cfg.OutsideConfig != nil {
		err := cfg.OutsideConfig.Validate()
		if err != nil {
			return err
		}
	}

	if cfg.LocalConfig == nil && cfg.OutsideConfig == nil {
		return common.NewBasicError("No rate limiting configured (both local and outside config missing)", nil)
	}
	return nil
}

func (cfg PacketRateLimitConfig) ConfigName() string {
	return "packetRateLimit"
}

func (cfg PacketRateLimitConfig) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteSample(dst, path, nil,
		config.StringSampler{
			Text: rateLimitSample,
			Name: "LocalConfig",
		},
		config.StringSampler{
			Text: rateLimitSample,
			Name: "OutsideConfig",
		},
	)
}
