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

package whitelisting

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/whitelisting/whitelist_filters"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
)

var _ filters.PacketFilter = (*WhitelistFilter)(nil)

type WhitelistFilter struct {
	localIA addr.IA

	LocalFilter   *whitelist_filters.WLFilter
	OutsideFilter *whitelist_filters.WLFilter
}

func NewWhitelistFilterFromConfig(cfg *WhitelistConfig) (*WhitelistFilter, error) {
	err := cfg.Validate()
	if err != nil {
		return nil, err
	}

	topo, _ := getTopo(cfg.PathToTopoFile)

	return &WhitelistFilter{
		topo.ISD_AS,
		localFilter(cfg),
		outsideFilter(cfg, topo.ISD_AS.I)}, nil
}

func (f *WhitelistFilter) FilterPacket(pkt *snet.SCIONPacket) (filters.FilterResult, error) {

	address := pkt.Source

	if address.IA == f.localIA {
		return (*f.LocalFilter).FilterAddress(pkt.Source)
	}
	return (*f.OutsideFilter).FilterAddress(pkt.Source)
}

func (f *WhitelistFilter) SCMPError() scmp.ClassType {
	return scmp.ClassType{
		Class: scmp.C_Filtering,
		Type:  scmp.T_F_NotOnWhitelist,
	}
}

func localFilter(cfg *WhitelistConfig) *whitelist_filters.WLFilter {
	var lf whitelist_filters.WLFilter

	switch cfg.LocalSetting.LocalWLSetting {
	case AcceptLocal:
		lf = &whitelist_filters.AcceptingFilter{}
	case AcceptInfraNodes:
		lf = whitelist_filters.NewInfraNodesFilter(
			cfg.PathToTopoFile,
			cfg.RescanInterval.Duration)
	default:
		lf = &whitelist_filters.DroppingFilter{}
	}
	return &lf
}

func outsideFilter(cfg *WhitelistConfig, isd addr.ISD) *whitelist_filters.WLFilter {
	var of whitelist_filters.WLFilter

	switch cfg.OutsideSetting.OutsideWLSetting {
	case Accept:
		of = &whitelist_filters.AcceptingFilter{}
	case AcceptISD:
		of = &whitelist_filters.ISDFilter{Isd: isd}
	case AcceptNeighbours:
		of = whitelist_filters.NewNeighbourFilter(
			cfg.PathToTopoFile,
			cfg.RescanInterval.Duration)
	case AcceptUpstreamNeighbours:
		of = whitelist_filters.NewUpNeighbourFilter(
			cfg.PathToTopoFile,
			cfg.RescanInterval.Duration)
	case AcceptDownstreamNeighbours:
		of = whitelist_filters.NewDownNeighbourFilter(
			cfg.PathToTopoFile,
			cfg.RescanInterval.Duration)
	case AcceptCoreNeighbours:
		of = whitelist_filters.NewCoreNeighbourFilter(
			cfg.PathToTopoFile,
			cfg.RescanInterval.Duration)
	default:
		of = &whitelist_filters.DroppingFilter{}
	}
	return &of
}

func getTopo(pathToTopoFile string) (*topology.Topo, error) {
	return topology.LoadFromFile(pathToTopoFile)
}
