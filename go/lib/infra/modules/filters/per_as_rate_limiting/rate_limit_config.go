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

const (
	RateLimitSample = `
# number of clients to dimension the filter
NumOfClients = 100

# interval in which the filter gets reset
Interval = "20s"

# maximum of requests a client/AS can send per interval
MaxCount = 5
`
	//5 minutes default interval
	defaultInterval = 300 * time.Second

	//expected is 60 packets for non core, 120 for core ASes, plus 30% is 78 resp. 156 packets
	defaultMaxCount uint32 = 156
)

var _ config.Config = (*RateLimitConfig)(nil)

type RateLimitConfig struct {
	NumOfClients int
	Interval     duration
	MaxCount     int
}

func (cfg *RateLimitConfig) InitDefaults() {

	if cfg.Interval.Duration == 0 {
		cfg.Interval = duration{defaultInterval}
	}
	if cfg.MaxCount == 0 {
		cfg.MaxCount = int(defaultMaxCount)
	}
}

func (cfg RateLimitConfig) Validate() error {
	if cfg.NumOfClients <= 0 {
		return common.NewBasicError("Number of local clients is negative or zero", nil)
	}
	if cfg.Interval.Duration <= 0 {
		return common.NewBasicError("Local interval is negative or zero", nil)
	}
	if cfg.MaxCount <= 0 || cfg.MaxCount >= 65536 {
		return common.NewBasicError("Local Max count is smaller or equal to zero", nil)
	}
	return nil
}

func (cfg RateLimitConfig) ConfigName() string {
	return "ratelimit"
}

func (cfg RateLimitConfig) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, RateLimitSample)
}

type duration struct {
	time.Duration
}

func (d *duration) UnmarshalText(text []byte) error {
	var err error
	d.Duration, err = time.ParseDuration(string(text))
	return err
}
