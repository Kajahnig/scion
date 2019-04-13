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

package integration

import (
	"flag"

	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/filter_creation"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	FilterConfigDir = "./go/integration/filter_configs"
)

var (
	ConfigFileName string
)

func SetupWithFilters() {
	addFlags()
	addFilterFlags()
	validateFlags()
	validateFilterFlags()
	if Mode == ModeServer {
		initNetworkWithFilterDispatcher()
	} else {
		initNetwork()
	}
}

func addFilterFlags() {
	flag.StringVar(&ConfigFileName, "config", "",
		"(Mandatory for servers) Name of the filter config file in "+FilterConfigDir)
}

func validateFilterFlags() {
	if Mode == ModeServer {
		if ConfigFileName == "" {
			LogFatal("Missing filter config file")
		}
	}
}

func initNetworkWithFilterDispatcher() {
	// Initialize custom scion network with filter dispatcher
	err := snet.InitCustom(Local.IA, Sciond, filters.NewFilteringPacketDispatcher(createFilters()))

	if err != nil {
		LogFatal("Unable to initialize custom SCION network with filter dispatcher", "err", err)
	}
	log.Debug("SCION network successfully initialized")
}

func createFilters() []*filters.PacketFilter {
	filters, err := filter_creation.CreateFiltersFromConfigFile(FilterConfigDir, ConfigFileName)
	if err != nil {
		LogFatal("Unable to create filters", "err", err)
	}
	return filters
}