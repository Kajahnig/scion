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
	"io"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/config"
)

const (
	Nothing = ""
	//shared WL settings
	DropWL = "Drop"
	//local WL settings
	InfraWL = "Infra"
	//outside WL settings
	ISDWL        = "ISD"
	NeighboursWL = "Neighbours"
	UpWL         = "UpNeighbours"
	DownWL       = "DownNeighbours"
	CoreWL       = "CoreNeighbours"
	//local rate limit settings
	IntervalRL = "Interval"
	HistoryRL  = "History"
	//segment filter settings
	Core    = "core"
	NonCore = "non-core"
)

const requestConfigSample = `
#internal IP whitelist settings
InternalWL = "Infra"

#external AS whitelist setting 
ExternalWL = "ISD"

#internal (per IP) traffic rate limit setting
InternalRateLimit = "Interval"

#external (per AS) traffic rate limit setting
ExternalRateLimit = "History"

#check AS internal traffic for empty path
CheckInternalForEmptyPath = true

#only accept traffic from neighbours (excluding peers)
LimitExternalToNeighbours = false

#filter number of segments for request from outside of the local ISD, 
# as a core server (max seg length 1) or non-core server (max seg length 2)
SegmentFiltering = "core"
`

var _ config.Config = (*RequestConfig)(nil)

type RequestConfig struct {
	InternalWL                string
	ExternalWL                string
	InternalRateLimit         string
	ExternalRateLimit         string
	CheckInternalForEmptyPath bool
	LimitExternalToNeighbours bool
	SegmentFiltering          string
}

func (cfg *RequestConfig) InitDefaults() {}

func (cfg RequestConfig) Validate() error {
	if cfg.InternalWL != Nothing && cfg.InternalWL != DropWL && cfg.InternalWL != InfraWL {
		return common.NewBasicError("Invalid internal whitelist setting", nil, "setting", cfg.InternalWL)
	}
	if cfg.ExternalWL != Nothing && cfg.ExternalWL != DropWL && cfg.ExternalWL != ISDWL &&
		cfg.ExternalWL != NeighboursWL && cfg.ExternalWL != UpWL && cfg.ExternalWL != DownWL &&
		cfg.ExternalWL != CoreWL {
		return common.NewBasicError("Invalid external whitelist setting", nil, "setting", cfg.ExternalWL)
	}
	if cfg.InternalRateLimit != Nothing && cfg.InternalRateLimit != IntervalRL && cfg.InternalRateLimit != HistoryRL {
		return common.NewBasicError("Invalid internal rate limit setting", nil,
			"setting", cfg.InternalRateLimit)
	}
	if cfg.ExternalRateLimit != Nothing && cfg.ExternalRateLimit != IntervalRL && cfg.ExternalRateLimit != HistoryRL {
		return common.NewBasicError("Invalid internal rate limit setting", nil,
			"setting", cfg.ExternalRateLimit)
	}
	if cfg.SegmentFiltering != Nothing {
		if cfg.LimitExternalToNeighbours {
			return common.NewBasicError("Segment filtering and neighbour filtering both set", nil)
		}
		if cfg.SegmentFiltering != Core && cfg.SegmentFiltering != NonCore {
			return common.NewBasicError("Invalid segment filter setting", nil,
				"setting", cfg.SegmentFiltering)
		}

	}
	return nil
}

func (cfg RequestConfig) ConfigName() string {
	return "request"
}

func (cfg RequestConfig) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, requestConfigSample)
}
