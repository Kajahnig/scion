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
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/path_length"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/whitelisting"
	"github.com/scionproto/scion/go/lib/log"
)

const (
	Whitelist  = "whitelist"
	PathLength = "pathLength"
	Comment    = "//"
)

func CreateFiltersFromConfigFile(configDir string, configFileName string) ([]*filters.PacketFilter, error) {
	configFile, err := os.Open(configDir + "/" + configFileName)
	if err != nil {
		return nil, err
	}
	defer configFile.Close()

	scanner := bufio.NewScanner(configFile)
	var results []*filters.PacketFilter
	for scanner.Scan() {
		filter, err, add := createFilter(scanner.Text(), configDir)
		if err != nil {
			return nil, err
		}
		if add {
			results = append(results, filter)
			log.Debug(fmt.Sprintf("Added %v filter to PacketFilter slice", reflect.TypeOf(*filter)))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

func createFilter(filterConfig string, configDir string) (*filters.PacketFilter, error, bool) {
	configParams := strings.Fields(filterConfig)

	if len(configParams) == 0 {
		return nil, nil, false
	}

	log.Debug("Trying to create Filter from string " + filterConfig)

	var filter filters.PacketFilter
	var err error

	switch configParams[0] {
	case Whitelist:
		filter, err = whitelisting.NewWhitelistFilterFromStrings(configParams[1:], configDir)
	case PathLength:
		filter, err = path_length.NewPathLengthFilterFromStrings(configParams[1:])
	default:
		if strings.HasPrefix(configParams[0], Comment) {
			return nil, nil, false
		}
		err = common.NewBasicError("No matching filter found for configuration", nil, "line", filterConfig)
	}

	if err != nil {
		return nil, err, false
	}
	log.Debug("Successfully created " + configParams[0] + " filter")
	return &filter, nil, true
}
