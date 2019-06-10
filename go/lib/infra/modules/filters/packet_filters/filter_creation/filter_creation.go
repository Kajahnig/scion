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
	"github.com/scionproto/scion/go/lib/infra/modules/filters/packet_filters"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/packet_filters/drkey_filter"
)

func CreateFiltersFromConfig(cfg PacketFilterConfig) ([]*packet_filters.PacketFilter, error) {

	var results []*packet_filters.PacketFilter

	if cfg.Drkey != nil {
		var filter packet_filters.PacketFilter
		filter = drkey_filter.NewDRKeyFilterFromConfig(cfg.Drkey)
		results = append(results, &filter)
	}
	return results, nil
}
