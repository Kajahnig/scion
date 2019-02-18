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

package filters

import (
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/snet"
)

type FilterResult int

const (
	// FilterError means the current filter has encountered an error.
	FilterError FilterResult = iota
	// FilterAccept means the packet was accepted by this particular filter
	// and should be handed to the next one.
	FilterAccept
	// FilterDrop means the current filter does not accept this packet,
	// and it needs to be dropped.
	FilterDrop
)

type AddrFilter interface {
	FilterAddr(addr *snet.Addr) (FilterResult, error)
}

type PacketFilter interface {
	FilterPacket(pkt *snet.SCIONPacket) (FilterResult, error)
	SCMPError() scmp.ClassType
}
