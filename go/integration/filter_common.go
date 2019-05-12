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

	"github.com/BurntSushi/toml"

	"github.com/scionproto/scion/go/lib/infra/modules/filters/packet_filters"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/packet_filters/filter_creation"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	FilterConfigDir = "./go/integration/filter_configs"
)

var (
	PacketFilterConfig string
)

func SetupWithPacketFilters() {
	addFlags()
	addFilterFlags()
	validateFlags()
	if Mode == ModeServer && PacketFilterConfig != "" {
		initNetworkWithFilterDispatcher()
	} else {
		initNetwork()
	}
}

func addFilterFlags() {
	flag.StringVar(&PacketFilterConfig, "pfConfig", "",
		"(Mandatory for servers) Name of the packet filter configuration in "+FilterConfigDir)
}

func initNetworkWithFilterDispatcher() {
	// Initialize custom scion network with filter dispatcher
	err := snet.InitCustom(Local.IA, Sciond, packet_filters.NewFilteringPacketDispatcher(createFiltersFromConfig()))

	if err != nil {
		LogFatal("Unable to initialize custom SCION network with filter dispatcher", "err", err)
	}
	log.Debug("SCION network with filter dispatcher successfully initialized")
}

func createFiltersFromConfig() []*packet_filters.PacketFilter {
	var cfg filter_creation.PacketFilterConfig
	_, err := toml.DecodeFile(FilterConfigDir+"/"+PacketFilterConfig+".toml", &cfg)

	if err != nil {
		LogFatal("Error decoding toml file", "err", err)
	}

	cfg.InitDefaults()
	err = cfg.Validate()
	if err != nil {
		LogFatal("Validation of Filter configuration failed", "err", err)
	}
	filters, err := filter_creation.CreateFiltersFromConfig(cfg)
	if err != nil {
		LogFatal("Unable to create filters", "err", err)
	}
	return filters
}
