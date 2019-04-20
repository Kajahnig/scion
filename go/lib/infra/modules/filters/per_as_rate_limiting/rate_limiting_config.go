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
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/config"
)

const perASRateLimitSample = `
# set number of local clients
LocalClients = 100

# set number of ASes
OutsideASes = 5

# set local interval
LocalInterval = "20s"

# set outside interval
OutsideInterval = "50s"

#set local max count
LocalMaxCount = 1

#set outside max count
OutsideMaxCount = 3
`

var _ config.Config = (*PerASRateLimitConfig)(nil)

type PerASRateLimitConfig struct {
	LocalClients    int
	OutsideASes     int
	LocalInterval   duration
	OutsideInterval duration
	LocalMaxCount   int
	OutsideMaxCount int
}

func (cfg *PerASRateLimitConfig) InitDefaults() {

	if cfg.LocalClients > 0 {
		if cfg.LocalInterval.Duration == 0 {
			cfg.LocalInterval = duration{defaultInterval}
		}
		if cfg.LocalMaxCount == 0 {
			cfg.LocalMaxCount = int(defaultMaxCount)
		}
	}
	if cfg.OutsideASes > 0 {
		if cfg.OutsideInterval.Duration == 0 {
			cfg.OutsideInterval = duration{defaultInterval}
		}
		if cfg.OutsideMaxCount == 0 {
			cfg.OutsideMaxCount = int(defaultMaxCount)
		}
	}
}

func (cfg *PerASRateLimitConfig) Validate() error {
	if cfg.LocalClients < 0 {
		return common.NewBasicError("Number of local clients is negative", nil)
	} else if cfg.LocalClients > 0 {
		if cfg.LocalInterval.Duration <= 0 {
			return common.NewBasicError("Local interval is negative or zero", nil)
		}
		if cfg.LocalMaxCount <= 0 || cfg.LocalMaxCount >= 65536 {
			return common.NewBasicError("Local Max count is smaller or equal to zero", nil)
		}
	}
	if cfg.OutsideASes < 0 {
		return common.NewBasicError("Number of outside ASes is negative", nil)
	} else if cfg.OutsideASes > 0 {
		if cfg.OutsideInterval.Duration <= 0 {
			return common.NewBasicError("Outside interval is negative or zero", nil)
		}
		if cfg.OutsideMaxCount <= 0 || cfg.OutsideMaxCount >= 65536 {
			return common.NewBasicError("Outside Max count is smaller or equal to zero", nil)
		}
	}
	if cfg.LocalClients == 0 && cfg.OutsideASes == 0 {
		return common.NewBasicError("No rate limiting configured (client and AS count both missing)", nil)
	}
	return nil
}

func (cfg *PerASRateLimitConfig) ConfigName() string {
	return "perASratelimit"
}

func (cfg *PerASRateLimitConfig) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, perASRateLimitSample)
}

type duration struct {
	time.Duration
}

func (d *duration) UnmarshalText(text []byte) error {
	var err error
	d.Duration, err = time.ParseDuration(string(text))
	return err
}
