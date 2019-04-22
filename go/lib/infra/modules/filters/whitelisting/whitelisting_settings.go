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

type OutsideWLSetting int
type LocalWLSetting int

const (
	//Settings for Filtering requests from outside the local AS
	//Drop All requests from outside of the local AS
	Drop OutsideWLSetting = iota
	//Accept all traffic
	Accept
	// Whitelist all requests form the local ISD
	AcceptISD
	// Whitelist only the requests from neighbouring ASes
	AcceptNeighbours
	// Whitelist only the requests from neighbouring upstream ASes
	AcceptUpstreamNeighbours
	//Whitelists only the requests from neighbouring downstream ASes
	AcceptDownstreamNeighbours
	//Whitelist only requests from core neighbours
	AcceptCoreNeighbours
)

func (setting OutsideWLSetting) toString() string {
	switch setting {
	case Drop:
		return "Drop outside traffic"
	case Accept:
		return "Accept outside traffic"
	case AcceptISD:
		return "Accept traffic of local ISD"
	case AcceptNeighbours:
		return "Accept traffic of neighbours"
	case AcceptUpstreamNeighbours:
		return "Accept traffic of upstream neighbours"
	case AcceptDownstreamNeighbours:
		return "Accept traffic of downstream neighbours"
	case AcceptCoreNeighbours:
		return "Accept traffic of core neighbours"
	default:
		return "Unknown outside whitelisting setting"
	}
}

const (
	//Settings for Filtering requests from the local AS
	// Drop all requests from the local AS
	DropLocal LocalWLSetting = iota
	// Whitelist only local requests from infrastructure nodes
	AcceptInfraNodes
	// Accept all requests
	AcceptLocal
)

func (setting LocalWLSetting) toString() string {
	switch setting {
	case AcceptLocal:
		return "Accept traffic of local AS"
	case AcceptInfraNodes:
		return "Accept traffic of local infra nodes"
	case DropLocal:
		return "Drop local traffic"
	default:
		return "Unknown local whitelisting setting"
	}
}
