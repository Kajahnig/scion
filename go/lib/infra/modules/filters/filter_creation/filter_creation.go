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

package filter_creation

import (
	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/drkey_filter"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/path_length"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/per_as_rate_limiting"
)

func CreateFiltersFromConfig(cfg PacketFilterConfig) ([]*filters.PacketFilter, error) {

	var results []*filters.PacketFilter
	var err error

	if cfg.Pathlength != nil {
		var filter filters.PacketFilter
		filter, err = path_length.NewPathLengthFilterFromConfig(cfg.Pathlength)
		if err != nil {
			return nil, err
		}
		results = append(results, &filter)
	}
	if cfg.Drkey != nil {
		var filter filters.PacketFilter
		filter = &drkey_filter.DRKeyFilter{}
		results = append(results, &filter)
	}
	if cfg.PacketRateLimit != nil {
		var filter filters.PacketFilter
		filter, err = per_as_rate_limiting.NewPacketRateLimitingFilterFromConfig(cfg.PacketRateLimit)
		if err != nil {
			return nil, err
		}
		results = append(results, &filter)
	}
	return results, nil
}
