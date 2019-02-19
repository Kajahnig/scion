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
	NoOutsideWL OutsideWLSetting = iota
	// Whitelist all requests form the local ISD
	WLISD
	// Whitelist only the requests from neighbouring ASes
	WLAllNeighbours
	// Whitelist only the requests from neighbouring up- or downstream ASes
	WLUpAndDownNeighbours
	//Whitelists only core neighbours
	WLCoreNeighbours
)

func (setting OutsideWLSetting) toString() string {
	switch setting {
	case NoOutsideWL:
		return "No outside whitelisting"
	case WLISD:
		return "Whitelisting of ISD"
	case WLAllNeighbours:
		return "Whitelisting of all neighbours"
	case WLUpAndDownNeighbours:
		return "Whitelisting of up and downstream neighbours"
	case WLCoreNeighbours:
		return "Whitelisting of core neighbours"
	default:
		return "Unknown outside whitelisting setting"
	}
}

const (
	//Settings for Filtering requests from the local AS
	// Whitelist all requests form the local AS
	WLLocalAS LocalWLSetting = iota
	// Whitelist only local requests from infrastructure nodes
	WLLocalInfraNodes
	// Drop All requests from the local AS
	NoLocalWL
)

func (setting LocalWLSetting) toString() string {
	switch setting {
	case WLLocalAS:
		return "Whitelisting of local AS"
	case WLLocalInfraNodes:
		return "Whitelisting of local infra nodes"
	case NoLocalWL:
		return "No Local Whitelisting"
	default:
		return "Unknown local whitelisting setting"
	}
}
