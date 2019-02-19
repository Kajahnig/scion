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
	"bufio"
	"os"
	"strings"

	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/path_length"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/whitelisting"
	"github.com/scionproto/scion/go/lib/log"
)

var (
	whitelist  = "whitelist"
	pathLength = "pathLength"
)

func CreateFiltersFromConfigFile(pathToConfigFile string) ([]*filters.PacketFilter, error) {
	configFile, err := os.Open(pathToConfigFile)
	if err != nil {
		return nil, err
	}
	defer configFile.Close()

	scanner := bufio.NewScanner(configFile)
	var results []*filters.PacketFilter
	for scanner.Scan() {
		filter, err, add := createFilter(scanner.Text())
		if err != nil {
			return nil, err
		}
		if add {
			results = append(results, filter)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

func createFilter(filterConfig string) (*filters.PacketFilter, error, bool) {
	configParams := strings.Fields(filterConfig)

	switch configParams[0] {
	case whitelist:
		filter, err := whitelisting.NewWhitelistFilterFromStrings(configParams[1:])
		packetFilter := filters.PacketFilter(filter)
		return &packetFilter, err, true
	case pathLength:
		filter, err := path_length.NewPathLengthFilterFromStrings(configParams[1:])
		packetFilter := filters.PacketFilter(filter)
		return &packetFilter, err, true
	default:
		if !strings.HasPrefix(configParams[0], "//") {
			log.Error("Filter creation ignored a non-comment line in the config file",
				"line", filterConfig)
		}
		return nil, nil, false
	}
}
