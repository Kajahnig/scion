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
	"strconv"
	"strings"

	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/path_length"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/whitelisting"
	"github.com/scionproto/scion/go/lib/log"
)

var (
	whitelist                 = "whitelist"
	path_flag                 = "-path"
	rescanInterval_flag       = "-interval"
	outsideWL_flag            = "-outside"
	ISD_value                 = "ISD"
	allNeighbours_value       = "allN"
	upAndDownNeighbours_value = "upDownN"
	coreNeighbours_value      = "coreN"
	no_value                  = "no"
	localWL_flag              = "-local"
	AS_value                  = "AS"
	infra_value               = "infra"

	pathLength     = "pathLength"
	minLength_flag = "-min"
	maxLength_flag = "-max"
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
		filter, err := createWhitelistFilter(configParams[1:])
		return filter, err, true
	case pathLength:
		filter, err := createPathLengthFilter(configParams[1:])
		return filter, err, true
	default:
		if !strings.HasPrefix(configParams[0], "//") {
			log.Error("Filter creation ignored a non-comment line in the config file",
				"line", filterConfig)
		}
		return nil, nil, false
	}
}

func createWhitelistFilter(configParams []string) (*filters.PacketFilter, error) {
	var pathToTopoFile string
	var rescanInterval float64 = -1
	var outsideSettings = whitelisting.OutsideWLSetting(10)
	var localSettings = whitelisting.LocalWLSetting(10)
	var err error

	for i := 0; i < len(configParams); i += 2 {
		switch configParams[i] {
		case path_flag:
			pathToTopoFile = configParams[i+1]
			continue
		case rescanInterval_flag:
			rescanInterval, err = strconv.ParseFloat(configParams[i+1], 64)
			if err != nil {
				return nil, err
			}
			continue
		case outsideWL_flag:
			switch configParams[i+1] {
			case ISD_value:
				outsideSettings = whitelisting.WLISD
			case allNeighbours_value:
				outsideSettings = whitelisting.WLAllNeighbours
			case upAndDownNeighbours_value:
				outsideSettings = whitelisting.WLUpAndDownNeighbours
			case coreNeighbours_value:
				outsideSettings = whitelisting.WLCoreNeighbours
			case no_value:
				outsideSettings = whitelisting.NoOutsideWL
			}
			continue
		case localWL_flag:
			switch configParams[i+1] {
			case AS_value:
				localSettings = whitelisting.WLLocalAS
			case infra_value:
				localSettings = whitelisting.WLLocalInfraNodes
			case no_value:
				localSettings = whitelisting.NoLocalWL
			}
		}
	}

	filter, err := whitelisting.NewWhitelistFilter(pathToTopoFile, rescanInterval,
		outsideSettings, localSettings)
	if err != nil {
		return nil, err
	}
	var packetFilter = filters.PacketFilter(filter)

	return &packetFilter, nil
}

func createPathLengthFilter(configParams []string) (*filters.PacketFilter, error) {
	var minLength = -1
	var maxLength = -1

	for i := 0; i < len(configParams); i += 2 {
		switch configParams[i] {
		case minLength_flag:
			minLength64, err := strconv.ParseInt(configParams[i+1], 10, 32)
			if err != nil {
				return nil, err
			}
			minLength = int(minLength64)
		case maxLength_flag:
			maxLength64, err := strconv.ParseInt(configParams[i+1], 10, 32)
			if err != nil {
				return nil, err
			}
			maxLength = int(maxLength64)
		}
	}

	filter, err := path_length.NewPathLengthFilter(minLength, maxLength)
	if err != nil {
		return nil, err
	}
	var packetFilter = filters.PacketFilter(filter)

	return &packetFilter, nil
}
